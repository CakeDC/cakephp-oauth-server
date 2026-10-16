<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Http;

use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Http\RequestPaths;

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
}
