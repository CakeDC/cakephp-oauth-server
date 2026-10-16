<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Http;

use Cake\Routing\Route\Route;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Path handling for the places the plugin scopes bearer tokens to: the same normalisation the router
 * applies, prefix matching on segment boundaries, and the static part of the route the router matched.
 *
 * @internal
 */
final class RequestPaths
{
    /**
     * A path as the router sees it: each segment URL-decoded on its own, no trailing slash (the root is `/`).
     *
     * It fails closed, returning null (no match, never skip anything) where the router and a plain string
     * comparison could disagree: an encoded slash (`%2F` in any case; the router keeps it inside one segment),
     * an empty interior segment (`//`, the router does not collapse it) and `.` or `..` segments.
     *
     * @param string $path The path, without a query string.
     * @return string|null
     */
    public static function normalize(string $path): ?string
    {
        if (preg_match('/%2f/i', $path) === 1) {
            return null;
        }
        $segments = explode('/', str_starts_with($path, '/') ? $path : '/' . $path);
        array_shift($segments);
        if ($segments !== [] && end($segments) === '') {
            array_pop($segments);
        }
        $decoded = [];
        foreach ($segments as $segment) {
            $value = urldecode($segment);
            if ($value === '' || $value === '.' || $value === '..' || str_contains($value, '/')) {
                return null;
            }
            $decoded[] = $value;
        }

        return '/' . implode('/', $decoded);
    }

    /**
     * The path of $request below the host: the application's base directory plus the routed path.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return string|null Normalized, or null for a path with dot segments.
     */
    public static function fullPath(ServerRequestInterface $request): ?string
    {
        $base = $request->getAttribute('base');

        return self::normalize((is_string($base) ? $base : '') . $request->getUri()->getPath());
    }

    /**
     * The static part of the template of the route that matched $request, with the base directory in front:
     * what the router decided, where the path only says what the URL looks like.
     *
     * A template that starts with a placeholder (`/{tenant}/account/delete`, `/{slug}`, the fallbacks) fixes
     * nothing but the root, `/`, even when the request path is `/api/account/delete`. When the static part
     * ends inside a segment (`/api-{version}`, `/api{suffix}`), only the complete segments before it count.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return string|null Normalized; null when the request has no matched route (routing has not run yet).
     */
    public static function routePath(ServerRequestInterface $request): ?string
    {
        $route = $request->getAttribute('route');
        if (!$route instanceof Route) {
            return null;
        }
        $static = $route->staticPath();
        $rest = substr($route->template, strlen($static));
        if ($rest !== '' && !str_ends_with($static, '/') && !str_starts_with($rest, '/')) {
            // The static part stops inside a segment, so that segment is not fixed.
            $static = substr($static, 0, (int)strrpos($static, '/') + 1);
        }
        $base = $request->getAttribute('base');

        return self::normalize((is_string($base) ? $base : '') . $static);
    }

    /**
     * Whether $request lies within $prefixes both by its path and by the route the router matched for it.
     * A request without a matched route is never within.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param list<string> $prefixes Normalized prefixes.
     * @return bool
     */
    public static function routedWithin(ServerRequestInterface $request, array $prefixes): bool
    {
        return self::within(self::fullPath($request), $prefixes)
            && self::within(self::routePath($request), $prefixes);
    }

    /**
     * The normalized path of a resource identifier (a URL); `/` for the host root.
     *
     * @param string $identifier The resource identifier.
     * @return string
     */
    public static function ofResource(string $identifier): string
    {
        $path = parse_url($identifier, PHP_URL_PATH);

        return self::normalize(is_string($path) ? $path : '') ?? '/';
    }

    /**
     * Whether $path equals one of the prefixes or lies below it, on a segment boundary: `/api` covers `/api`
     * and `/api/x` but not `/apix`. The prefix `/` covers everything.
     *
     * @param string|null $path A normalized path; null never matches.
     * @param list<string> $prefixes Normalized prefixes.
     * @return bool
     */
    public static function within(?string $path, array $prefixes): bool
    {
        if ($path === null) {
            return false;
        }
        foreach ($prefixes as $prefix) {
            if ($prefix === '/' || $path === $prefix || str_starts_with($path, $prefix . '/')) {
                return true;
            }
        }

        return false;
    }
}
