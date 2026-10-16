<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Model\Table;

use Cake\Database\Schema\TableSchemaInterface;
use Cake\ORM\Table;

/**
 * OAuth clients.
 */
class OauthClientsTable extends Table
{
    /**
     * @param array<string, mixed> $config Configuration.
     * @return void
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('oauth_clients');
        $this->setPrimaryKey('id');
        $this->setDisplayField('name');
    }

    /**
     * Maps the JSON text columns.
     *
     * @return \Cake\Database\Schema\TableSchemaInterface
     */
    public function getSchema(): TableSchemaInterface
    {
        return parent::getSchema()
            ->setColumnType('redirect_uris', 'json')
            ->setColumnType('grant_types', 'json')
            ->setColumnType('scopes', 'json')
            ->setColumnType('metadata', 'json');
    }
}
