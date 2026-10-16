<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Storage;

/**
 * The whole storage contract again, under a non-UTC default timezone: stored instants must not shift.
 */
class OrmStorageNonUtcTest extends OrmStorageTest
{
    protected string $previousTimezone = 'UTC';

    /**
     * @return void
     */
    protected function setUp(): void
    {
        $this->previousTimezone = date_default_timezone_get();
        date_default_timezone_set('America/Lima');
        parent::setUp();
    }

    /**
     * @return void
     */
    protected function tearDown(): void
    {
        parent::tearDown();
        date_default_timezone_set($this->previousTimezone);
    }
}
