<?php
declare(strict_types=1);

// cakephp/migrations 4 (CakePHP 5.0 to 5.2) runs phinx-style AbstractMigration classes, 5 only
// BaseMigration: extend whichever this installation has.
if (!class_exists('CakeDCOAuthServerMigration', false)) {
    class_alias(
        class_exists('Migrations\\AbstractMigration') ? 'Migrations\\AbstractMigration' : 'Migrations\\BaseMigration',
        'CakeDCOAuthServerMigration',
    );
}

/**
 * The OAuth server tables, the same shape as the core's schema/*.sql.
 *
 * Ids are fixed width strings (CHAR(36)), never native UUID columns: ids reach storage from request
 * input and a malformed one must simply not match instead of raising on PostgreSQL. On MySQL and
 * MariaDB the tables are created with the binary collation utf8mb4_bin, so subjects and ids compare
 * case and accent sensitively.
 *
 * Apps that copy plugin migrations into their own config/Migrations can copy this file unchanged.
 */
class CreateOAuthServerTables extends CakeDCOAuthServerMigration
{
    /**
     * @return void
     */
    public function up(): void
    {
        $this->table('oauth_clients', $this->tableOptions())
            ->addColumn('id', 'char', ['limit' => 36, 'null' => false])
            ->addColumn('client_id', 'text', ['null' => false])
            ->addColumn('client_id_hash', 'char', ['limit' => 64, 'null' => false])
            ->addColumn('type', 'string', ['limit' => 20, 'null' => false])
            ->addColumn('application_type', 'string', ['limit' => 10, 'null' => false])
            ->addColumn('name', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('client_uri', 'text', ['null' => true])
            ->addColumn('logo_uri', 'text', ['null' => true])
            ->addColumn('redirect_uris', 'text', ['null' => false])
            ->addColumn('grant_types', 'text', ['null' => false])
            ->addColumn('scopes', 'text', ['null' => true])
            ->addColumn('token_endpoint_auth_method', 'string', ['limit' => 30, 'null' => false])
            ->addColumn('secret_hash', 'char', ['limit' => 64, 'null' => true])
            ->addColumn('allow_introspection', 'boolean', ['null' => false, 'default' => false])
            ->addColumn('metadata', 'text', ['null' => true])
            ->addColumn('metadata_fetched_at', 'datetime', ['null' => true])
            ->addColumn('metadata_expires_at', 'datetime', ['null' => true])
            ->addColumn('last_used_at', 'datetime', ['null' => true])
            ->addColumn('revoked_at', 'datetime', ['null' => true])
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addIndex(['client_id_hash'], ['unique' => true, 'name' => 'oauth_clients_client_id_hash'])
            ->create();

        $this->table('oauth_authorization_codes', $this->tableOptions())
            ->addColumn('id', 'char', ['limit' => 36, 'null' => false])
            ->addColumn('code_hash', 'char', ['limit' => 64, 'null' => false])
            ->addColumn('oauth_client_id', 'char', ['limit' => 36, 'null' => false])
            ->addColumn('subject', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('redirect_uri', 'text', ['null' => false])
            ->addColumn('resource', 'text', ['null' => false])
            ->addColumn('scopes', 'text', ['null' => false])
            ->addColumn('code_challenge', 'string', ['limit' => 128, 'null' => false])
            ->addColumn('family_id', 'char', ['limit' => 36, 'null' => true])
            ->addColumn('expires_at', 'datetime', ['null' => false])
            ->addColumn('used_at', 'datetime', ['null' => true])
            ->addColumn('created', 'datetime', ['null' => false])
            ->addIndex(['code_hash'], ['unique' => true, 'name' => 'oauth_authorization_codes_code_hash'])
            ->addIndex(['oauth_client_id'], ['name' => 'oauth_authorization_codes_oauth_client_id'])
            ->addIndex(['expires_at'], ['name' => 'oauth_authorization_codes_expires_at'])
            ->addForeignKey('oauth_client_id', 'oauth_clients', 'id', [
                'delete' => 'CASCADE',
                'update' => 'NO_ACTION',
                'constraint' => 'oauth_authorization_codes_client',
            ])
            ->create();

        $this->table('oauth_tokens', $this->tableOptions())
            ->addColumn('id', 'char', ['limit' => 36, 'null' => false])
            ->addColumn('token_hash', 'char', ['limit' => 64, 'null' => false])
            ->addColumn('type', 'string', ['limit' => 10, 'null' => false])
            ->addColumn('family_id', 'char', ['limit' => 36, 'null' => false])
            ->addColumn('parent_id', 'char', ['limit' => 36, 'null' => true])
            ->addColumn('oauth_client_id', 'char', ['limit' => 36, 'null' => true])
            ->addColumn('subject', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('subject_type', 'string', ['limit' => 10, 'null' => false])
            ->addColumn('resource', 'text', ['null' => false])
            ->addColumn('scopes', 'text', ['null' => false])
            ->addColumn('name', 'string', ['limit' => 255, 'null' => true])
            ->addColumn('expires_at', 'datetime', ['null' => true])
            ->addColumn('used_at', 'datetime', ['null' => true])
            ->addColumn('revoked_at', 'datetime', ['null' => true])
            ->addColumn('last_used_at', 'datetime', ['null' => true])
            ->addColumn('family_started_at', 'datetime', ['null' => true])
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addIndex(['token_hash'], ['unique' => true, 'name' => 'oauth_tokens_token_hash'])
            ->addIndex(['family_id'], ['name' => 'oauth_tokens_family_id'])
            ->addIndex(['subject', 'subject_type'], ['name' => 'oauth_tokens_subject_subject_type'])
            ->addIndex(['oauth_client_id'], ['name' => 'oauth_tokens_oauth_client_id'])
            ->addIndex(['expires_at'], ['name' => 'oauth_tokens_expires_at'])
            ->addIndex(['revoked_at'], ['name' => 'oauth_tokens_revoked_at'])
            ->addForeignKey('oauth_client_id', 'oauth_clients', 'id', [
                'delete' => 'CASCADE',
                'update' => 'NO_ACTION',
                'constraint' => 'oauth_tokens_client',
            ])
            ->create();

        $this->table('oauth_consents', $this->tableOptions())
            ->addColumn('id', 'char', ['limit' => 36, 'null' => false])
            ->addColumn('subject', 'string', ['limit' => 255, 'null' => false])
            ->addColumn('oauth_client_id', 'char', ['limit' => 36, 'null' => false])
            ->addColumn('resource', 'text', ['null' => false])
            ->addColumn('resource_hash', 'char', ['limit' => 64, 'null' => false])
            ->addColumn('scopes', 'text', ['null' => false])
            ->addColumn('created', 'datetime', ['null' => false])
            ->addColumn('modified', 'datetime', ['null' => false])
            ->addIndex(
                ['subject', 'oauth_client_id', 'resource_hash'],
                ['unique' => true, 'name' => 'oauth_consents_unique'],
            )
            ->addIndex(['oauth_client_id'], ['name' => 'oauth_consents_oauth_client_id'])
            ->addForeignKey('oauth_client_id', 'oauth_clients', 'id', [
                'delete' => 'CASCADE',
                'update' => 'NO_ACTION',
                'constraint' => 'oauth_consents_client',
            ])
            ->create();
    }

    /**
     * @return void
     */
    public function down(): void
    {
        foreach (['oauth_consents', 'oauth_tokens', 'oauth_authorization_codes', 'oauth_clients'] as $table) {
            $this->table($table)->drop()->save();
        }
    }

    /**
     * Table options shared by the four tables: the string id as primary key, and the binary collation
     * on MySQL and MariaDB only.
     *
     * @return array<string, mixed>
     */
    private function tableOptions(): array
    {
        $options = ['id' => false, 'primary_key' => ['id']];
        if ($this->getAdapter()->getAdapterType() === 'mysql') {
            $options['encoding'] = 'utf8mb4';
            $options['collation'] = 'utf8mb4_bin';
        }

        return $options;
    }
}
