<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support;

use CakeDC\OAuth\Server\Client\Cimd\FetchedResponse;
use CakeDC\OAuth\Server\Client\Cimd\HttpTransportInterface;
use RuntimeException;

/**
 * Serves metadata documents from memory instead of the network.
 */
class FakeTransport implements HttpTransportInterface
{
    /**
     * @var array<string, \CakeDC\OAuth\Server\Client\Cimd\FetchedResponse>
     */
    public array $responses = [];

    /**
     * Serves $document at $url.
     *
     * @param string $url The metadata document URL.
     * @param array<string, mixed> $document The document.
     * @param string $cacheControl The Cache-Control header.
     * @return void
     */
    public function serve(string $url, array $document, string $cacheControl = 'max-age=600'): void
    {
        $this->responses[$url] = new FetchedResponse(
            200,
            ['content-type' => 'application/json', 'cache-control' => $cacheControl],
            (string)json_encode($document),
        );
    }

    /**
     * @inheritDoc
     */
    public function get(string $url, string $ip, int $timeout, int $maxBytes): FetchedResponse
    {
        return $this->responses[$url] ?? throw new RuntimeException('Could not resolve host');
    }
}
