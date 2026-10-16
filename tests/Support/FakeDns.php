<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support;

use CakeDC\OAuth\Server\Client\Cimd\DnsResolverInterface;

/**
 * Answers DNS lookups from a fixed table; claude.ai resolves to an address of its egress range.
 */
class FakeDns implements DnsResolverInterface
{
    /**
     * @var array<string, list<string>>
     */
    public array $answers = ['claude.ai' => ['160.79.104.10']];

    /**
     * @inheritDoc
     */
    public function resolve(string $host): array
    {
        return $this->answers[$host] ?? [];
    }
}
