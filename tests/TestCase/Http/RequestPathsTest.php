<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Http;

use Cake\Http\ServerRequest;
use Cake\Routing\Route\Route;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Http\RequestPaths;
use CakeDC\OAuthServer\Test\Support\Routed;

class RequestPathsTest extends TestCase
{
    public function testNormalize(): void
    {
        $this->assertSame('/', RequestPaths::normalize(''));
        $this->assertSame('/', RequestPaths::normalize('/'));
        $this->assertSame('/api', RequestPaths::normalize('/api/'));
        $this->assertSame('/api/x', RequestPaths::normalize('api/x'));
        $this->assertSame('/api/x', RequestPaths::normalize('/%61pi/x'));
        $this->assertSame('/api%2Fx', RequestPaths::normalize('/api%252Fx'));
        $this->assertSame('/a b', RequestPaths::normalize('/a%20b'));
        // Fail closed where the router and a string comparison could disagree.
        foreach (['///', '//api/x', '/api//x', '/api/x//', '/api%2Fx', '/api%2fx/y', '/oauth%2Ftoken', '/%2F'] as $path) {
            $this->assertNull(RequestPaths::normalize($path), $path);
        }
        $this->assertNull(RequestPaths::normalize('/api/../x'));
        $this->assertNull(RequestPaths::normalize('/api/./x'));
        $this->assertNull(RequestPaths::normalize('/api/%2e%2e/x'));
        $this->assertSame('/api/..x', RequestPaths::normalize('/api/..x'));
    }

    public function testWithinMatchesOnSegmentBoundaries(): void
    {
        $this->assertTrue(RequestPaths::within('/api', ['/api']));
        $this->assertTrue(RequestPaths::within('/api/x', ['/api']));
        $this->assertFalse(RequestPaths::within('/apix', ['/api']));
        $this->assertFalse(RequestPaths::within('/ap', ['/api']));
        $this->assertTrue(RequestPaths::within('/b/c', ['/a', '/b']));
        $this->assertTrue(RequestPaths::within('/anything', ['/']));
        $this->assertTrue(RequestPaths::within('/', ['/']));
        $this->assertFalse(RequestPaths::within('/', ['/api']));
        $this->assertFalse(RequestPaths::within(null, ['/']));
        $this->assertFalse(RequestPaths::within('/api', []));
    }

    public function testOfResource(): void
    {
        $this->assertSame('/api', RequestPaths::ofResource('http://localhost/api'));
        $this->assertSame('/api/v1', RequestPaths::ofResource('https://example.com/api/v1/'));
        $this->assertSame('/', RequestPaths::ofResource('http://localhost'));
        $this->assertSame('/', RequestPaths::ofResource('http://localhost/'));
    }

    public function testFullPathAddsTheBase(): void
    {
        $request = new ServerRequest(['url' => '/api/me/']);

        $this->assertSame('/api/me', RequestPaths::fullPath($request));
        $this->assertSame('/sub/api/me', RequestPaths::fullPath($request->withAttribute('base', '/sub')));
        $this->assertNull(RequestPaths::fullPath(new ServerRequest(['url' => '/a/../b'])));
    }

    public function testRoutePathIsTheStaticPartOfTheMatchedRouteWithTheBase(): void
    {
        $route = fn(string $template, string $base = ''): ?string => RequestPaths::routePath(
            Routed::request('/x', $template)->withAttribute('base', $base),
        );

        $this->assertSame('/api/me', $route('/api/me'));
        $this->assertSame('/api', $route('/api/'));
        $this->assertSame('/api', $route('/api/**'));
        $this->assertSame('/api', $route('/api/*'));
        $this->assertSame('/api', $route('/api/{id}'));
        $this->assertSame('/api/v1', $route('/api/v1/{controller}/{action}/*'));
        // A template that starts with a placeholder fixes nothing but the root.
        $this->assertSame('/', $route('/{tenant}/account/delete'));
        $this->assertSame('/', $route('/{slug}'));
        $this->assertSame('/', $route('/{controller}/{action}/*'));
        $this->assertSame('/', $route('/*'));
        $this->assertSame('/', $route('/'));
        // A static part that ends inside a segment fixes only the complete segments before it.
        $this->assertSame('/', $route('/api-{version}/x'));
        $this->assertSame('/', $route('/api{suffix}/account/delete'));
        $this->assertSame('/v1', $route('/v1/api{suffix}'));
        $this->assertSame('/', $route('/api*'));
        // The base directory comes first.
        $this->assertSame('/sub/api', $route('/api/**', '/sub'));
        $this->assertSame('/sub', $route('/{slug}', '/sub'));
    }

    public function testRoutePathOfATemplateWithoutALeadingSlashIsTheRoot(): void
    {
        // Cake's builders always add the slash; a Route built by hand need not. Its static part has no slash at
        // all, so no complete segment is fixed: the root, never the first character of the template.
        $route = fn(string $template, string $base = ''): ?string => RequestPaths::routePath(
            (new ServerRequest(['url' => '/x']))->withAttribute('route', new Route($template))->withAttribute('base', $base),
        );

        $this->assertSame('/', $route('api-{version}'));
        $this->assertSame('/', $route('a{x}/account/delete'));
        $this->assertSame('/', $route('{slug}'));
        $this->assertSame('/sub', $route('api-{version}', '/sub'));
    }

    public function testRoutePathIsNullBeforeRouting(): void
    {
        $this->assertNull(RequestPaths::routePath(new ServerRequest(['url' => '/api/me'])));
        $this->assertNull(RequestPaths::routePath(
            (new ServerRequest(['url' => '/api/me']))->withAttribute('route', '/api/me'),
        ));
    }

    public function testRoutedWithinNeedsBothThePathAndTheMatchedRoute(): void
    {
        $within = fn(string $url, ?string $template, array $prefixes, string $base = ''): bool => RequestPaths::routedWithin(
            Routed::request($url, $template)->withAttribute('base', $base),
            $prefixes,
        );

        $this->assertTrue($within('/api/me', '/api/me', ['/api']));
        $this->assertTrue($within('/api/deeper/down', '/api/**', ['/api']));
        // The path looks like the resource's, but the router picked a route that is not below it.
        $this->assertFalse($within('/api/account/delete', '/{tenant}/account/delete', ['/api']));
        $this->assertFalse($within('/api', '/{slug}', ['/api']));
        $this->assertTrue($within('/api/account/delete', '/{tenant}/account/delete', ['/']));
        // The route is below, the path is not.
        $this->assertFalse($within('/account/delete', '/api/**', ['/api']));
        // Not routed yet: nothing is within, not even the root.
        $this->assertFalse($within('/api/me', null, ['/']));
        // Both carry the base directory.
        $this->assertFalse($within('/api/me', '/api/me', ['/api'], '/sub'));
        $this->assertTrue($within('/api/me', '/api/me', ['/sub/api'], '/sub'));
    }
}
