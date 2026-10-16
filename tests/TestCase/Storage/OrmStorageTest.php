<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Storage;

use Cake\ORM\Locator\LocatorAwareTrait;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Testing\StorageContractTestCase;
use CakeDC\OAuthServer\Storage\OrmStorage;

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
}
