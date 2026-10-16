<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Storage;

use Cake\Log\Engine\ArrayLog;
use Cake\ORM\Locator\LocatorAwareTrait;
use CakeDC\OAuth\Server\Grant\Consent;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Support\Uuid;
use CakeDC\OAuth\Server\Testing\StorageContractTestCase;
use CakeDC\OAuthServer\Storage\OrmStorage;
use DateTimeImmutable;
use DateTimeZone;
use Throwable;

/**
 * The core's storage contract, on the plugin's ORM tables (SQLite by default; DB_URL for MySQL or PostgreSQL).
 */
class OrmStorageTest extends StorageContractTestCase
{
    use LocatorAwareTrait;

    /**
     * @return \CakeDC\OAuth\Server\Storage\StorageInterface
     */
    protected function createStorage(): StorageInterface
    {
        foreach (['OauthConsents', 'OauthTokens', 'OauthAuthorizationCodes', 'OauthClients'] as $table) {
            $this->fetchTable('CakeDC/OAuthServer.' . $table)->deleteAll([]);
        }

        return new OrmStorage();
    }

    /**
     * Ids reach storage from the connections form: one that is not shaped like the ids the core generates
     * (invalid UTF-8 on PostgreSQL makes the query itself fail) matches nothing and never reaches the database.
     *
     * @return void
     */
    public function testMalformedIdsMatchNothingWithoutAQuery(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $driver = $this->fetchTable('CakeDC/OAuthServer.OauthTokens')->getConnection()->getDriver();
        $log = new ArrayLog();
        $driver->setLogger($log);
        $driver->enableQueryLogging();
        try {
            foreach (["\xFF\xFE", 'not-a-uuid', '', strtoupper($client->id) . 'x', $client->id . "\n", "' OR '1'='1"] as $id) {
                $this->assertNull($storage->findClientById($id), bin2hex($id));
                $this->assertNull($storage->findTokenById($id), bin2hex($id));
                $this->assertSame([], $storage->findTokensByFamily($id), bin2hex($id));
            }
            $this->assertSame([], $log->read());
            // Control: a well-formed id is looked up.
            $this->assertNotNull($storage->findClientById($client->id));
            $this->assertNotSame([], $log->read());
        } finally {
            $driver->disableQueryLogging();
        }
    }

    /**
     * @return void
     */
    public function testSavingACodeWithAnExistingIdThrowsAndKeepsTheRow(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $code = $this->makeCode($client);
        $storage->saveCode($code);
        $familyId = Uuid::v4();
        $this->assertTrue($storage->consumeCode($code->id, $this->at(5), $familyId));

        try {
            $storage->saveCode($code);
            $this->fail('A duplicate code id must be rejected');
        } catch (Throwable) {
            // Expected.
        }

        $stored = $storage->findCodeByHash($code->codeHash);
        $this->assertEquals($this->at(5), $stored?->usedAt);
        $this->assertFalse($storage->consumeCode($code->id, $this->at(9), $familyId));
    }

    /**
     * @return void
     */
    public function testSavingATokenWithAnExistingIdThrowsAndKeepsTheRow(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $token = $this->makeToken($client);
        $storage->saveToken($token);
        $storage->revokeToken($token->id, $this->at(7));

        try {
            $storage->saveToken($token);
            $this->fail('A duplicate token id must be rejected');
        } catch (Throwable) {
            // Expected.
        }

        $this->assertEquals($this->at(7), $storage->findTokenById($token->id)?->revokedAt);
    }

    /**
     * @return void
     */
    public function testAConsentInsertedByARacingRequestIsUpdated(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $table = $this->fetchTable('CakeDC/OAuthServer.OauthConsents');
        $table->getEventManager()->on('Model.beforeSave', function () use ($client, $table): void {
            $table->getEventManager()->off('Model.beforeSave');
            $table->getConnection()->insert('oauth_consents', [
                'id' => Uuid::v4(),
                'subject' => '42',
                'oauth_client_id' => $client->id,
                'resource' => 'https://example.com/mcp',
                'resource_hash' => hash('sha256', 'https://example.com/mcp'),
                'scopes' => '["old"]',
                'created' => '2026-01-01 00:00:00',
                'modified' => '2026-01-01 00:00:00',
            ]);
        });

        $storage->saveConsent(new Consent(
            Uuid::v4(),
            '42',
            $client->id,
            'https://example.com/mcp',
            ['content:read'],
            $this->at(100),
            $this->at(100),
        ));

        $consents = $storage->findConsentsBySubject('42');
        $this->assertCount(1, $consents);
        $this->assertSame(['content:read'], $consents[0]->scopes);
        $this->assertEquals($this->at(100), $consents[0]->modifiedAt);
    }

    /**
     * @return void
     */
    public function testWritesStoreTheUtcWallTimeOfAnInstantInAnotherZone(): void
    {
        $storage = $this->createStorage();
        $client = $this->makeClient();
        $storage->saveClient($client);
        $at = new DateTimeImmutable('2026-03-05 10:00:00', new DateTimeZone('America/Lima'));
        $storage->touchClient($client->id, $at);
        $token = $this->makeToken($client);
        $storage->saveToken($token);
        $storage->touchToken($token->id, $at);

        $connection = $this->fetchTable('CakeDC/OAuthServer.OauthClients')->getConnection();
        $raw = $connection->execute('SELECT last_used_at FROM oauth_clients WHERE id = ?', [$client->id])->fetch();
        $this->assertSame('2026-03-05 15:00:00', substr((string)$raw[0], 0, 19));
        $raw = $connection->execute('SELECT last_used_at FROM oauth_tokens WHERE id = ?', [$token->id])->fetch();
        $this->assertSame('2026-03-05 15:00:00', substr((string)$raw[0], 0, 19));
        $this->assertEquals($at, $storage->findTokenById($token->id)?->lastUsedAt);
    }
}
