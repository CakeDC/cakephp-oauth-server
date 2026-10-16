<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support;

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\Resource\ProtectedResource;

class StubUserProvider implements UserProviderInterface
{
    /**
     * @param array<string, mixed> $config Settings.
     */
    public function __construct(public readonly array $config = [])
    {
    }

    /**
     * @inheritDoc
     */
    public function findBySubject(string $subject): ?ResourceOwner
    {
        return null;
    }

    /**
     * @inheritDoc
     */
    public function canAuthorize(ResourceOwner $owner, Client $client, ProtectedResource $resource): bool
    {
        return false;
    }

    /**
     * @inheritDoc
     */
    public function scopesFor(ResourceOwner $owner, ProtectedResource $resource): ?array
    {
        return null;
    }

    /**
     * @inheritDoc
     */
    public function forClient(Client $client, ProtectedResource $resource): ?ResourceOwner
    {
        return null;
    }
}
