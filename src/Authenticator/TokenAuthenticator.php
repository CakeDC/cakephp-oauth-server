<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Authenticator;

use Authentication\Authenticator\AbstractAuthenticator;
use Authentication\Authenticator\AuthenticationRequiredException;
use Authentication\Authenticator\Result;
use Authentication\Authenticator\ResultInterface;
use Authentication\Authenticator\StatelessInterface;
use Authentication\Identifier\IdentifierInterface;
use CakeDC\OAuth\Server\Token\ValidationFailure;
use CakeDC\OAuthServer\Http\RequestPaths;
use CakeDC\OAuthServer\Identity\OAuthIdentity;
use CakeDC\OAuthServer\OAuthServer;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Authenticates requests carrying a bearer token of this server, below the path of the token's resource.
 * Load it as `CakeDC/OAuthServer.Token`.
 *
 * A token is for one resource, and that resource lives at its URL: the `paths` option (default: the path of the
 * resource identifier, `/api` for `http://localhost/api`) lists the path prefixes where the authenticator
 * authenticates, matched on segment boundaries. A request that carries this server's token outside them is
 * challenged with 401 and never authenticated, so a token for the API cannot act as the person on the
 * application's session pages. A resource at the host root needs `paths` set explicitly (`['/']` covers every
 * route).
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

    private string $resource;

    /**
     * @var list<string>
     */
    private array $paths;

    private ?string $failure = null;

    /**
     * @param \Authentication\Identifier\IdentifierInterface $identifiers Unused, required by the interface.
     * @param array<string, mixed> $config Configuration.
     * @throws \InvalidArgumentException When the resource is not declared in the server configuration, when `paths`
     *   is invalid, or when the resource is at the host root and `paths` is not set.
     */
    public function __construct(IdentifierInterface $identifiers, array $config = [])
    {
        parent::__construct($identifiers, $config);
        $resources = OAuthServer::server()->config()->resources;
        $resource = $this->getConfig('resource');
        if ($resource === null) {
            $this->resource = $resources->defaultResource()->identifier;
        } elseif (!is_string($resource) || $resources->get($resource) === null) {
            throw new InvalidArgumentException(sprintf(
                'The resource "%s" of the Token authenticator is not declared in OAuthServer.resources.',
                is_string($resource) ? $resource : get_debug_type($resource),
            ));
        } else {
            $this->resource = $resource;
        }
        $this->paths = $this->resolvePaths($this->getConfig('paths'));
    }

    /**
     * The path prefixes where the authenticator authenticates.
     *
     * @param mixed $paths The `paths` option.
     * @return list<string>
     * @throws \InvalidArgumentException
     */
    private function resolvePaths(mixed $paths): array
    {
        if ($paths === null) {
            $path = RequestPaths::ofResource($this->resource);
            if ($path === '/') {
                throw new InvalidArgumentException(sprintf(
                    'The resource "%s" is at the host root, so its token would be accepted on every route. '
                    . 'Set the "paths" option of the Token authenticator explicitly: a list of path prefixes, '
                    . 'or [\'/\'] to accept the token on every route.',
                    $this->resource,
                ));
            }

            return [$path];
        }
        $normalized = [];
        foreach (is_array($paths) ? $paths : [] as $path) {
            $value = is_string($path) && str_starts_with($path, '/') ? RequestPaths::normalize($path) : null;
            if ($value === null) {
                throw new InvalidArgumentException(
                    'The "paths" option of the Token authenticator must be a non-empty list of path prefixes '
                    . 'that start with "/".',
                );
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
        if (!RequestPaths::within(RequestPaths::fullPath($request), $this->paths)) {
            $this->failure = 'The access token is not valid at this address.';

            return new Result(null, Result::FAILURE_CREDENTIALS_INVALID, [$this->failure]);
        }
        $result = OAuthServer::server()->tokenValidator()->validate($token, $this->resource);
        if ($result instanceof ValidationFailure) {
            $this->failure = $result->description;

            return new Result(null, Result::FAILURE_CREDENTIALS_INVALID, [$result->description]);
        }

        return new Result(new OAuthIdentity($result), Result::SUCCESS);
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
     * The bearer token of the request when it carries this server's access or personal prefix, or null.
     */
    private function ownToken(ServerRequestInterface $request): ?string
    {
        $header = $request->getHeaderLine((string)$this->getConfig('header'));
        if (preg_match('/^Bearer +([A-Za-z0-9\-._~+\/]+=*) *\z/i', $header, $matches) !== 1) {
            return null;
        }
        $prefix = OAuthServer::server()->config()->tokenPrefix;
        if (!str_starts_with($matches[1], $prefix . '_at_') && !str_starts_with($matches[1], $prefix . '_pat_')) {
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
