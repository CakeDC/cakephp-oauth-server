<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Model\Table;

use Cake\Database\Schema\TableSchemaInterface;
use Cake\ORM\Table;

/**
 * OAuth authorization codes.
 */
class OauthAuthorizationCodesTable extends Table
{
    /**
     * @param array<string, mixed> $config Configuration.
     * @return void
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('oauth_authorization_codes');
        $this->setPrimaryKey('id');
    }

    /**
     * Maps the JSON text columns.
     *
     * @return \Cake\Database\Schema\TableSchemaInterface
     */
    public function getSchema(): TableSchemaInterface
    {
        return parent::getSchema()
            ->setColumnType('scopes', 'json');
    }
}
