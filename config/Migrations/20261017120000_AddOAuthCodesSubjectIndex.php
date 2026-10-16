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
 * An index on `oauth_authorization_codes.subject`, as in the core's schema/*.sql: revoking a person or one of their
 * connections deletes the codes they have not exchanged yet by subject.
 *
 * It only adds an index, so it is safe on a database that already has it (created from the core's SQL files).
 * Apps that copy plugin migrations into their own config/Migrations can copy this file unchanged.
 */
class AddOAuthCodesSubjectIndex extends CakeDCOAuthServerMigration
{
    private const INDEX = 'oauth_authorization_codes_subject';

    /**
     * @return void
     */
    public function up(): void
    {
        $table = $this->table('oauth_authorization_codes');
        if (!$table->hasIndexByName(self::INDEX)) {
            $table->addIndex(['subject'], ['name' => self::INDEX])->update();
        }
    }

    /**
     * @return void
     */
    public function down(): void
    {
        $table = $this->table('oauth_authorization_codes');
        if ($table->hasIndexByName(self::INDEX)) {
            $table->removeIndexByName(self::INDEX)->update();
        }
    }
}
