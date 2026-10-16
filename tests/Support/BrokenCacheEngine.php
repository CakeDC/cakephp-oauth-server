<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support;

use Cake\Cache\CacheEngine;
use DateInterval;
use RuntimeException;

/**
 * A cache whose backend is down: every read and write throws, as a Redis engine does when Redis is gone.
 */
final class BrokenCacheEngine extends CacheEngine
{
    public function get(string $key, mixed $default = null): mixed
    {
        throw new RuntimeException('Connection refused');
    }

    public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
    {
        throw new RuntimeException('Connection refused');
    }

    public function increment(string $key, int $offset = 1): int|false
    {
        throw new RuntimeException('Connection refused');
    }

    public function decrement(string $key, int $offset = 1): int|false
    {
        throw new RuntimeException('Connection refused');
    }

    public function delete(string $key): bool
    {
        throw new RuntimeException('Connection refused');
    }

    public function clear(): bool
    {
        throw new RuntimeException('Connection refused');
    }

    public function clearGroup(string $group): bool
    {
        throw new RuntimeException('Connection refused');
    }
}
