<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Storage;

use Cake\Database\Connection;
use Cake\Database\Driver\Mysql;
use Cake\Database\Driver\Postgres;
use Cake\Datasource\ConnectionManager;
use Cake\ORM\Locator\LocatorAwareTrait;
use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Support\Uuid;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenType;
use CakeDC\OAuthServer\Storage\OrmStorage;
use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\TestCase;

/**
 * A real race between two processes: a request is inserting a token for a client (its transaction is still open,
 * so the row is not visible yet, but its foreign key check holds a lock on the client) while prune() picks that
 * client as unused. prune() must wait for the insert and keep the client; it must not delete the client and let
 * the database cascade the new token away once the insert commits.
 *
 * On PostgreSQL the claim UPDATE alone does not wait (it changes no key column and the insert holds only a
 * key-share lock), so this pins the `SELECT ... FOR UPDATE` that prune() takes first. On MySQL and MariaDB prune()
 * already waits at its first statement (deleting old tokens scans the row being inserted), so the test passes there
 * whatever prune() does with the client. Runs when DB_URL points at MySQL, MariaDB or PostgreSQL and proc_open() is
 * available.
 */
class PruneLockTest extends TestCase
{
    use LocatorAwareTrait;

    private const MONITOR = 'oauth_prune_monitor';

    protected function tearDown(): void
    {
        if (in_array(self::MONITOR, ConnectionManager::configured(), true)) {
            ConnectionManager::drop(self::MONITOR);
        }
        parent::tearDown();
    }

    public function testPruneWaitsForATokenInsertInFlightAndKeepsTheClient(): void
    {
        $url = (string)getenv('DB_URL');
        /** @var \Cake\Database\Connection $connection */
        $connection = ConnectionManager::get('test');
        $driver = $connection->getDriver();
        if ($url === '' || !$driver instanceof Mysql && !$driver instanceof Postgres) {
            $this->markTestSkipped('Needs DB_URL pointing at MySQL, MariaDB or PostgreSQL.');
        }
        if (!function_exists('proc_open')) {
            $this->markTestSkipped('proc_open() is disabled.');
        }
        foreach (['OauthConsents', 'OauthTokens', 'OauthAuthorizationCodes', 'OauthClients'] as $table) {
            $this->fetchTable('CakeDC/OAuthServer.' . $table)->deleteAll([]);
        }
        $storage = new OrmStorage();
        $now = new DateTimeImmutable('2026-06-01 12:00:00', new DateTimeZone('UTC'));
        // A dynamic client registered two months ago and never used: a pruning candidate.
        $client = new Client(
            id: Uuid::v4(),
            clientId: bin2hex(random_bytes(16)),
            type: ClientType::Dynamic,
            applicationType: ApplicationType::Web,
            name: 'Abandoned',
            redirectUris: ['https://app.example.com/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            authMethod: ClientAuthMethod::None,
            createdAt: $now->sub(new DateInterval('P60D')),
        );
        $storage->saveClient($client);
        $token = new Token(
            id: Uuid::v4(),
            tokenHash: hash('sha256', Uuid::v4()),
            type: TokenType::Access,
            familyId: Uuid::v4(),
            clientInternalId: $client->id,
            subject: '42',
            subjectType: SubjectType::User,
            resource: 'http://localhost/mcp',
            scopes: ['content:read'],
            createdAt: $now,
            expiresAt: $now->add(new DateInterval('PT1H')),
        );

        // The request: the token is inserted, the transaction not committed yet.
        $connection->begin();
        try {
            $storage->saveToken($token);
            $worker = $this->startWorker($url, $now);
            $this->waitUntilLocked($this->monitor($url), $worker['connection'], $worker['process']);
        } finally {
            $connection->commit();
        }
        $result = $this->finish($worker);

        $this->assertSame(0, $result['clients'], 'The client was pruned although a token was being saved.');
        $this->assertNotNull($storage->findClientById($client->id));
        $this->assertNotNull($storage->findTokenById($token->id), 'The new token was cascaded away.');
    }

    private function monitor(string $url): Connection
    {
        // Not persistent: Cake's MySQL driver reuses one persistent session per DSN, the test's own here.
        ConnectionManager::setConfig(self::MONITOR, ['url' => $url, 'cacheMetadata' => false, 'persistent' => false]);
        /** @var \Cake\Database\Connection */
        return ConnectionManager::get(self::MONITOR);
    }

    /**
     * @return array{process: resource, pipes: array<int, resource>, connection: string}
     */
    private function startWorker(string $url, DateTimeImmutable $now): array
    {
        $support = dirname(__DIR__, 2) . '/Support/';
        $process = proc_open(
            // With a line on standard output before the worker's own, as a deprecation would print.
            [
                PHP_BINARY,
                '-d',
                'auto_prepend_file=' . $support . 'stdout-noise.php',
                $support . 'prune-worker.php',
                $now->format(DATE_ATOM),
            ],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            ['OAUTH_PRUNE_DB_URL' => $url] + getenv(),
        );
        $this->assertIsResource($process);
        [$line, $noise] = $this->readMarkedLine($pipes[1], 'connection: ', 10.0);
        if ($line === '') {
            proc_terminate($process);
            $this->fail('The worker did not start: ' . $noise . stream_get_contents($pipes[2]));
        }

        return ['process' => $process, 'pipes' => $pipes, 'connection' => $line];
    }

    /**
     * Waits until the worker's connection waits on a row lock (what the insert in flight holds).
     *
     * @param \Cake\Database\Connection $monitor A connection of its own.
     * @param string $connection The worker's connection id.
     * @param resource $process The worker.
     * @return void
     */
    private function waitUntilLocked(Connection $monitor, string $connection, $process): void
    {
        // MySQL and MariaDB do not list an autocommit statement that waits on a row lock in innodb_trx; a statement
        // of prune() that runs for over a second on these few rows is waiting on one (TIME counts whole seconds).
        $sql = $monitor->getDriver() instanceof Postgres
            ? "SELECT COUNT(*) FROM pg_stat_activity WHERE pid = ? AND wait_event_type = 'Lock'"
            : "SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE ID = ? AND COMMAND = 'Query' AND TIME >= 2";
        $deadline = microtime(true) + 15.0;
        while (microtime(true) < $deadline) {
            if ((int)$monitor->execute($sql, [(int)$connection])->fetchColumn(0) > 0) {
                return;
            }
            if (!proc_get_status($process)['running']) {
                $this->fail('prune() finished without waiting for the token insert in flight.');
            }
            usleep(20000);
        }
        $this->fail('prune() never waited on the client row.');
    }

    /**
     * @param array{process: resource, pipes: array<int, resource>, connection: string} $worker The worker.
     * @return array{codes: int, tokens: int, clients: int}
     */
    private function finish(array $worker): array
    {
        [$line, $noise] = $this->readMarkedLine($worker['pipes'][1], 'result: ', 15.0);
        $errors = $noise . (string)stream_get_contents($worker['pipes'][2]);
        fclose($worker['pipes'][1]);
        fclose($worker['pipes'][2]);
        $exit = proc_close($worker['process']);
        $this->assertSame(0, $exit, 'The worker failed: ' . $line . $errors);
        $result = json_decode($line, true);
        $this->assertIsArray($result, 'Unexpected worker output: ' . $line . $errors);

        /** @var array{codes: int, tokens: int, clients: int} $result */
        return $result;
    }

    /**
     * The value of the first line that starts with $marker, and the other lines read before it.
     *
     * @param resource $pipe The pipe.
     * @param string $marker The start of the line.
     * @param float $timeout Seconds.
     * @return array{string, string} The value ('' when no such line came in time), and the other output.
     */
    private function readMarkedLine($pipe, string $marker, float $timeout): array
    {
        $deadline = microtime(true) + $timeout;
        $line = '';
        $noise = '';
        stream_set_blocking($pipe, false);
        while (microtime(true) < $deadline) {
            $chunk = fgets($pipe);
            if ($chunk !== false) {
                $line .= $chunk;
                if (str_ends_with($line, "\n")) {
                    if (str_starts_with($line, $marker)) {
                        return [trim(substr($line, strlen($marker))), $noise];
                    }
                    $noise .= $line;
                    $line = '';
                }
                continue;
            }
            if (feof($pipe)) {
                break;
            }
            usleep(10000);
        }

        return [str_starts_with($line, $marker) ? trim(substr($line, strlen($marker))) : '', $noise . $line];
    }
}
