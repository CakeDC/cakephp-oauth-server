<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Path handling for the places the plugin scopes bearer tokens to: the same normalisation the router
 * applies, and prefix matching on segment boundaries.
 *
 * @internal
 */
final class RequestPaths
{
    /**
     * A path as the router sees it: URL-decoded, duplicate slashes collapsed, no trailing slash (the root is
     * `/`). Null when the path has `.` or `..` segments, which nothing here may reason about.
     *
     * @param string $path The path, without a query string.
     * @return string|null
     */
    public static function normalize(string $path): ?string
    {
        $decoded = urldecode($path);
        $collapsed = (string)preg_replace('#/{2,}#', '/', '/' . $decoded);
        $segments = explode('/', $collapsed);
        if (in_array('.', $segments, true) || in_array('..', $segments, true)) {
            return null;
        }
        $trimmed = rtrim($collapsed, '/');

        return $trimmed === '' ? '/' : $trimmed;
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
