<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Authenticator;

use Authentication\Authenticator\AbstractAuthenticator;
use Authentication\Authenticator\AuthenticationRequiredException;
use Authentication\Authenticator\Result;
use Authentication\Authenticator\ResultInterface;
use Authentication\Authenticator\StatelessInterface;
use CakeDC\OAuth\Server\Token\ValidationFailure;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Http\RequestPaths;
use CakeDC\OAuthServer\Identity\OAuthIdentity;
use CakeDC\OAuthServer\Log\CakeLogger;
use CakeDC\OAuthServer\OAuthServer;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;

/**
 * Authenticates requests carrying a bearer token of this server, below the path of the token's resource.
 * Load it as `CakeDC/OAuthServer.Token`.
 *
 * A token is for one resource, and that resource lives at its URL: the `paths` option (default: the path of the
 * resource identifier, `/api` for `http://localhost/api`) lists the path prefixes where the authenticator
 * authenticates, matched on segment boundaries. Both the request path and the static part of the template of
 * the route that matched it must be within them: `/mcp/account/delete` routed by `/{tenant}/account/delete`
 * is outside `/mcp`, because the router, not the path, decides which action runs. A request that carries this
 * server's token outside them, or that was not routed yet, is challenged with 401 and never authenticated, so
 * a token for the API cannot act as the person on a session route that is not below the API's path. Routes
 * of a resource therefore need a static prefix within its paths. A resource at the host root needs `paths`
 * set explicitly (`['/']` covers every route).
 *
 * Building it reads no configuration, so a broken `OAuthServer` configuration (or a wrong `resource` or `paths`
 * option) cannot take every page of the application down. The resource, the paths and the server are resolved
 * on the first request that carries a bearer token with this server's prefix; when that fails the request is
 * refused with 401 (never passed on to the next authenticator) and the reason goes to the `oauth` log. When even
 * the `tokenPrefix` setting cannot be read, every bearer token is treated as this server's and refused.
 *
 * It is stateless: the identity is never persisted, so a bearer request cannot become a browser login.
 */
class TokenAuthenticator extends AbstractAuthenticator implements StatelessInterface
{
    /**
     * @var array<string, mixed>
     */
    protected array $_defaultConfig = [
        'resource' => null,
        'paths' => null,
        'header' => 'Authorization',
        'resourceMetadataUrl' => null,
        'skipTwoFactorVerify' => true,
    ];

    /**
     * @var array{resource: string, paths: list<string>}|null
     */
    private ?array $resolved = null;

    private ?string $failure = null;

    /**
     * The resource this authenticator validates tokens for and the path prefixes where it authenticates, from its
     * options and the `OAuthServer` configuration (read without the secret).
     *
     * @internal Used by the plugin and by `oauth check`; not part of the public API.
     * @return array{resource: string, paths: list<string>}
     * @throws \InvalidArgumentException When the resource is not declared in the server configuration, when `paths`
     *   is invalid, or when the resource is at the host root and `paths` is not set.
     */
    public function resolve(): array
    {
        if ($this->resolved !== null) {
            return $this->resolved;
        }
        $config = PluginConfig::fromConfigure();
        $option = $this->getConfig('resource');
        $resource = $option === null
            ? $config->defaultResourceIdentifier()
            : (is_string($option) ? $config->declaredResource($option) : null);
        if ($resource === null) {
            throw new InvalidArgumentException(sprintf(
                'The resource "%s" of the Token authenticator is not declared in OAuthServer.resources.',
                is_string($option) ? $option : get_debug_type($option),
            ));
        }

        return $this->resolved = ['resource' => $resource, 'paths' => $this->resolvePaths($resource)];
    }

    /**
     * The path prefixes where the authenticator authenticates.
     *
     * @param string $resource The resource identifier.
     * @return list<string>
     * @throws \InvalidArgumentException
     */
    private function resolvePaths(string $resource): array
    {
        $paths = $this->getConfig('paths');
        if ($paths === null) {
            $path = RequestPaths::ofResource($resource);
            if ($path === '/') {
                throw new InvalidArgumentException(sprintf(
                    'The resource "%s" is at the host root, so its token would be accepted on every route. '
                    . 'Set the "paths" option of the Token authenticator explicitly: a list of path prefixes, '
                    . 'or [\'/\'] to accept the token on every route.',
                    $resource,
                ));
            }

            return [$path];
        }
        $normalized = [];
        foreach (is_array($paths) ? $paths : [] as $path) {
            $value = is_string($path) && str_starts_with($path, '/') ? RequestPaths::normalize($path) : null;
            if ($value === null) {
                $normalized = [];
                break;
            }
            $normalized[] = $value;
        }
        if ($normalized === []) {
            throw new InvalidArgumentException(
                'The "paths" option of the Token authenticator must be a non-empty list of path prefixes '
                . 'that start with "/".',
            );
        }

        return $normalized;
    }

    /**
     * @inheritDoc
     */
    public function authenticate(ServerRequestInterface $request): ResultInterface
    {
        $this->failure = null;
        $token = $this->ownToken($request);
        if ($token === null) {
            return new Result(null, Result::FAILURE_CREDENTIALS_MISSING);
        }
        try {
            ['resource' => $resource, 'paths' => $paths] = $this->resolve();
        } catch (Throwable $e) {
            return $this->unusable(
                $request,
                'its resource and paths cannot be resolved from its options and the OAuthServer configuration',
                $e,
            );
        }
        if (!RequestPaths::routedWithin($request, $paths)) {
            $this->failure = 'The access token is not valid at this address.';

            return new Result(null, Result::FAILURE_CREDENTIALS_INVALID, [$this->failure]);
        }
        try {
            $validator = OAuthServer::server()->tokenValidator();
        } catch (Throwable $e) {
            return $this->unusable($request, 'the OAuth server cannot be built from the OAuthServer configuration', $e);
        }
        $result = $validator->validate($token, $resource);
        if ($result instanceof ValidationFailure) {
            $this->failure = $result->description;

            return new Result(null, Result::FAILURE_CREDENTIALS_INVALID, [$result->description]);
        }

        return new Result(new OAuthIdentity($result), Result::SUCCESS);
    }

    /**
     * Refuses a token of this server that cannot be checked because of the authenticator's options or the
     * configuration, and logs why.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param string $cause What could not be done.
     * @param \Throwable $error What failed.
     * @return \Authentication\Authenticator\ResultInterface
     */
    private function unusable(ServerRequestInterface $request, string $cause, Throwable $error): ResultInterface
    {
        (new CakeLogger())->error(
            'The Token authenticator refused a bearer token at {path}: {cause}. {message}',
            [
                'path' => $request->getUri()->getPath(),
                'cause' => $cause,
                'message' => $error->getMessage(),
                'exception' => $error,
            ],
        );
        $this->failure = 'The access token cannot be validated.';

        return new Result(null, Result::FAILURE_CREDENTIALS_INVALID, [$this->failure]);
    }

    /**
     * Challenges only requests that carried one of this server's tokens: anonymous requests and
     * other bearer schemes are left to the application and to the next authenticators.
     *
     * @inheritDoc
     */
    public function unauthorizedChallenge(ServerRequestInterface $request): void
    {
        if ($this->ownToken($request) === null) {
            return;
        }
        $description = $this->failure ?? 'The access token is invalid.';
        $parts = [];
        $metadata = $this->getConfig('resourceMetadataUrl');
        if (is_string($metadata) && $metadata !== '') {
            $parts[] = 'resource_metadata="' . self::quote($metadata) . '"';
        }
        $parts[] = 'error="invalid_token"';
        $parts[] = 'error_description="' . self::quote($description) . '"';

        throw new AuthenticationRequiredException(
            [
                'WWW-Authenticate' => 'Bearer ' . implode(', ', $parts),
                'Content-Type' => 'application/json',
                'Cache-Control' => 'no-store',
                'Pragma' => 'no-cache',
            ],
            (string)json_encode(['error' => 'invalid_token', 'error_description' => $description]),
        );
    }

    /**
     * The bearer token of the request when it carries this server's access or personal prefix, or null. The
     * prefix is read as configured, without building the server; when it cannot be read every bearer token
     * counts as this server's, so it is refused rather than passed on.
     */
    private function ownToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine((string)$this->getConfig('header'));
        if (preg_match('/^Bearer +([A-Za-z0-9\-._~+\/]+=*) *\z/i', $header, $matches) !== 1) {
            return null;
        }
        $prefix = PluginConfig::fromConfigure()->configuredTokenPrefix();
        if (
            $prefix !== null
            && !str_starts_with($matches[1], $prefix . '_at_')
            && !str_starts_with($matches[1], $prefix . '_pat_')
        ) {
            return null;
        }

        return $matches[1];
    }

    /**
     * A quoted-string value without control characters.
     */
    private static function quote(string $value): string
    {
        return str_replace(['\\', '"'], ['\\\\', '\\"'], preg_replace('/[\x00-\x1F\x7F]/', '', $value) ?? '');
    }
}
