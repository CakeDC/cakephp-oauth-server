<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\Support;

use Cake\Http\ServerRequest;
use Cake\Routing\Route\Route;

/**
 * Requests as RoutingMiddleware leaves them: with the route that matched in the `route` attribute.
 */
final class Routed
{
    /**
     * @param string $url The URL.
     * @param string|null $template Template of the matched route; null for a request that was not routed yet.
     * @param array<string, mixed> $config More request configuration (environment, cookies, ...).
     * @return \Cake\Http\ServerRequest
     */
    public static function request(string $url, ?string $template, array $config = []): ServerRequest
    {
        $request = new ServerRequest(['url' => $url] + $config);

        return $template === null ? $request : $request->withAttribute('route', new Route($template));
    }
}
