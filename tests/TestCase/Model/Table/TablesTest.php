<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Model\Table;

use Cake\Database\Connection;
use Cake\Database\Driver\Mysql;
use Cake\Database\Driver\Postgres;
use Cake\Datasource\ConnectionManager;
use Cake\I18n\DateTime;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Model\Table\OauthClientsTable;

class TablesTest extends TestCase
{
    /**
     * @var array<string>
     */
    protected array $tables = ['oauth_clients', 'oauth_authorization_codes', 'oauth_tokens', 'oauth_consents'];

    /**
     * @return \Cake\Database\Connection
     */
    protected function connection(): Connection
    {
        /** @var \Cake\Database\Connection */
        return ConnectionManager::get('test');
    }

    public function testTheMigrationCreatesTheFourTables(): void
    {
        $schema = $this->connection()->getSchemaCollection();
        $tables = $schema->listTables();

        foreach ($this->tables as $table) {
            $this->assertContains($table, $tables);
        }
        $this->assertContains('parent_id', $schema->describe('oauth_tokens')->columns());
        $this->assertContains('family_started_at', $schema->describe('oauth_tokens')->columns());
    }

    public function testTheCoreIndexSetExists(): void
    {
        $schema = $this->connection()->getSchemaCollection();
        $expected = [
            'oauth_clients' => ['oauth_clients_client_id_hash' => ['client_id_hash']],
            'oauth_authorization_codes' => [
                'oauth_authorization_codes_code_hash' => ['code_hash'],
                'oauth_authorization_codes_oauth_client_id' => ['oauth_client_id'],
                'oauth_authorization_codes_expires_at' => ['expires_at'],
            ],
            'oauth_tokens' => [
                'oauth_tokens_token_hash' => ['token_hash'],
                'oauth_tokens_family_id' => ['family_id'],
                'oauth_tokens_subject_subject_type' => ['subject', 'subject_type'],
                'oauth_tokens_oauth_client_id' => ['oauth_client_id'],
                'oauth_tokens_expires_at' => ['expires_at'],
                'oauth_tokens_revoked_at' => ['revoked_at'],
            ],
            'oauth_consents' => [
                'oauth_consents_unique' => ['subject', 'oauth_client_id', 'resource_hash'],
                'oauth_consents_oauth_client_id' => ['oauth_client_id'],
            ],
        ];
        foreach ($expected as $table => $indexes) {
            $described = $schema->describe($table);
            foreach ($indexes as $name => $columns) {
                $found = [];
                foreach ($described->indexes() as $indexName) {
                    $found[$indexName] = $described->getIndex($indexName)['columns'];
                }
                foreach ($described->constraints() as $constraintName) {
                    $constraint = $described->getConstraint($constraintName);
                    if ($constraint['type'] === 'unique') {
                        $found[$constraintName] = $constraint['columns'];
                    }
                }
                $this->assertArrayHasKey($name, $found, "{$table} lacks index {$name}");
                $this->assertSame($columns, $found[$name], "{$table}.{$name} covers other columns");
            }
        }
    }

    public function testIdsAreFixedWidthStringsNeverNativeUuids(): void
    {
        $columns = [
            'oauth_clients' => ['id'],
            'oauth_authorization_codes' => ['id', 'oauth_client_id', 'family_id'],
            'oauth_tokens' => ['id', 'family_id', 'parent_id', 'oauth_client_id'],
            'oauth_consents' => ['id', 'oauth_client_id'],
        ];
        $driver = $this->connection()->getDriver();
        foreach ($columns as $table => $names) {
            $described = $this->connection()->getSchemaCollection()->describe($table);
            foreach ($names as $name) {
                $column = $described->getColumn($name);
                $this->assertNotNull($column);
                // Cake reflects MySQL and SQLite CHAR(36) as its string-backed `uuid` type (no length),
                // PostgreSQL CHAR(36) as `string`. The raw checks below tell a real CHAR(36) from a native uuid.
                $this->assertContains($column['type'], ['uuid', 'char', 'string'], "{$table}.{$name}");
                if ($driver instanceof Postgres || $driver instanceof Mysql) {
                    $row = $this->connection()->execute(
                        'SELECT data_type AS dt, character_maximum_length AS len FROM information_schema.columns '
                        . 'WHERE table_name = ? AND column_name = ?'
                        . ($driver instanceof Mysql ? ' AND table_schema = DATABASE()' : ''),
                        [$table, $name],
                    )->fetch('assoc');
                    $this->assertContains($row['dt'], ['char', 'character'], "{$table}.{$name} is {$row['dt']}");
                    $this->assertSame(36, (int)$row['len'], "{$table}.{$name} is not CHAR(36)");
                }
            }
        }
    }

    public function testMysqlTablesAreBinaryCollated(): void
    {
        $driver = $this->connection()->getDriver();
        if (!$driver instanceof Mysql) {
            $this->markTestSkipped('Collation is a MySQL and MariaDB concern.');
        }
        foreach ($this->tables as $table) {
            $row = $this->connection()->execute(
                'SELECT TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
                [$table],
            )->fetch('assoc');
            $this->assertSame('utf8mb4_bin', $row['TABLE_COLLATION'], $table);
        }
    }

    public function testJsonColumnsRoundTrip(): void
    {
        /** @var \CakeDC\OAuthServer\Model\Table\OauthClientsTable $clients */
        $clients = $this->getTableLocator()->get('CakeDC/OAuthServer.OauthClients');
        $this->assertInstanceOf(OauthClientsTable::class, $clients);
        $now = new DateTime('2026-01-01 00:00:00');
        $entity = $clients->newEntity([
            'id' => '6f1c2f0a-0000-4000-8000-000000000001',
            'client_id' => 'abc',
            'client_id_hash' => hash('sha256', 'abc'),
            'type' => 'registered',
            'application_type' => 'web',
            'name' => 'App',
            'redirect_uris' => ['https://app.example.com/cb'],
            'grant_types' => ['authorization_code'],
            'scopes' => null,
            'token_endpoint_auth_method' => 'none',
            'allow_introspection' => false,
            'metadata' => ['nested' => ['a' => 1]],
            'created' => $now,
            'modified' => $now,
        ]);
        $clients->saveOrFail($entity);

        $loaded = $clients->get('6f1c2f0a-0000-4000-8000-000000000001');
        $this->assertSame(['https://app.example.com/cb'], $loaded->get('redirect_uris'));
        $this->assertSame(['nested' => ['a' => 1]], $loaded->get('metadata'));
        $this->assertNull($loaded->get('scopes'));
    }
}
