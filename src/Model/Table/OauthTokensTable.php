<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Model\Table;

use Cake\Database\Schema\TableSchemaInterface;
use Cake\ORM\Table;
use CakeDC\OAuthServer\Database\Type\UtcDateTimeType;

/**
 * OAuth tokens.
 */
class OauthTokensTable extends Table
{
    /**
     * @param array<string, mixed> $config Configuration.
     * @return void
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setTable('oauth_tokens');
        $this->setPrimaryKey('id');
    }

    /**
     * Maps the JSON text columns and pins the datetime columns to UTC.
     *
     * @return \Cake\Database\Schema\TableSchemaInterface
     */
    public function getSchema(): TableSchemaInterface
    {
        $schema = parent::getSchema()
            ->setColumnType('scopes', 'json');

        return UtcDateTimeType::apply($schema, [
            'expires_at',
            'used_at',
            'revoked_at',
            'last_used_at',
            'family_started_at',
            'created',
            'modified',
        ]);
    }
}
