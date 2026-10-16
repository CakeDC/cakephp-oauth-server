<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Database\Type;

use Cake\Database\Schema\TableSchemaInterface;
use Cake\Database\Type\DateTimeType;
use Cake\Database\TypeFactory;

/**
 * A datetime column type that always reads and writes UTC, whatever the application's default timezone is.
 *
 * Token lifetimes, the refresh grace window and the family cap are computed in UTC by the core.
 */
class UtcDateTimeType extends DateTimeType
{
    public const NAME = 'oauth_datetime';

    /**
     * Whether the type is registered already.
     */
    private static bool $mapped = false;

    /**
     * @param string|null $name The type name.
     */
    public function __construct(?string $name = null)
    {
        parent::__construct($name);
        $this->setDatabaseTimezone('UTC');
    }

    /**
     * Pins the given columns of a table schema to UTC.
     *
     * @param \Cake\Database\Schema\TableSchemaInterface $schema The schema.
     * @param array<string> $columns The datetime columns.
     * @return \Cake\Database\Schema\TableSchemaInterface
     */
    public static function apply(TableSchemaInterface $schema, array $columns): TableSchemaInterface
    {
        if (!self::$mapped) {
            TypeFactory::map(self::NAME, self::class);
            self::$mapped = true;
        }
        foreach ($columns as $column) {
            $schema->setColumnType($column, self::NAME);
        }

        return $schema;
    }
}
