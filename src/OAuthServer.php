<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer;

use Cake\Http\ResponseFactory;
use Cake\Http\ServerRequest;
use Cake\Http\StreamFactory;
use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuth\Server\Http\HttpResponder;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Server\ServerFactory;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Static entry point of the plugin for code that has no container at hand.
 */
final class OAuthServer
{
    private const CORE_STYLE_SRC = "style-src 'unsafe-inline'";

    private static ?AuthorizationServer $server = null;

    /**
     * The server, built once from `Configure::read('OAuthServer')`.
     *
     * @return \CakeDC\OAuth\Server\AuthorizationServer
     */
    public static function server(): AuthorizationServer
    {
        return self::$server ??= (new ServerFactory(PluginConfig::fromConfigure()))->create();
    }

    /**
     * A server whose pages render with $request.
     *
     * @param \Cake\Http\ServerRequest $request The current request.
     * @return \CakeDC\OAuth\Server\AuthorizationServer
     */
    public static function forRequest(ServerRequest $request): AuthorizationServer
    {
        return (new ServerFactory(PluginConfig::fromConfigure()))->create($request);
    }

    /**
     * Forgets the built server, for example after changing the configuration in a test.
     *
     * @return void
     */
    public static function reset(): void
    {
        self::$server = null;
    }

    /**
     * Whether $request goes to an endpoint OAuth clients call without a CSRF token (token, register,
     * revoke, introspect). Use it in CsrfProtectionMiddleware::skipCheckCallback().
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return bool
     */
    public static function csrfSkip(ServerRequestInterface $request): bool
    {
        $prefix = PluginConfig::fromConfigure()->routePrefix();
        $path = $request->getUri()->getPath();
        foreach (['token', 'register', 'revoke', 'introspect'] as $endpoint) {
            if ($path === $prefix . '/' . $endpoint) {
                return true;
            }
        }

        return false;
    }

    /**
     * The Content-Security-Policy a page needs when its layout is the application's, or null when the
     * page uses the plugin's own layout (the core's policy is then right as it is).
     *
     * The core sets the policy `default-src 'none'; style-src 'unsafe-inline'; ...` on every page. An
     * application layout normally links stylesheets, images and fonts of the same origin, so this adds
     * `style-src 'self'`, `img-src 'self' data:` and `font-src 'self'`. It never touches `script-src`
     * (layout scripts do not run), `frame-ancestors` or `base-uri`. The pages' controller applies the
     * result with `withHeader('Content-Security-Policy', ...)` after the core built the response.
     *
     * @param bool $connections True for the connections page, false for the consent and error pages.
     * @return string|null
     */
    public static function pageCsp(bool $connections = false): ?string
    {
        $config = PluginConfig::fromConfigure();
        $layout = $connections ? $config->connectionsLayout() : $config->consentLayout();
        if (!is_string($layout)) {
            return null;
        }
        $core = (new HttpResponder(new ResponseFactory(), new StreamFactory()))
            ->page('')
            ->getHeaderLine('Content-Security-Policy');
        if (!str_contains($core, self::CORE_STYLE_SRC)) {
            // The core's policy changed shape: keep it rather than guess.
            return null;
        }

        return str_replace(
            self::CORE_STYLE_SRC,
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'",
            $core,
        );
    }
}
