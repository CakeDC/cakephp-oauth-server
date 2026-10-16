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
use CakeDC\OAuthServer\Identity\OAuthIdentity;
use CakeDC\OAuthServer\OAuthServer;
use InvalidArgumentException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Authenticates requests carrying a bearer token of this server, for any route of the application.
 * Load it as `CakeDC/OAuthServer.Token`.
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
        'header' => 'Authorization',
        'resourceMetadataUrl' => null,
        'skipTwoFactorVerify' => true,
    ];

    private string $resource;

    private ?string $failure = null;

    /**
     * @param \Authentication\Identifier\IdentifierInterface $identifiers Unused, required by the interface.
     * @param array<string, mixed> $config Configuration.
     * @throws \InvalidArgumentException When the resource is not declared in the server configuration.
     */
    public function __construct(IdentifierInterface $identifiers, array $config = [])
    {
        parent::__construct($identifiers, $config);
        $resources = OAuthServer::server()->config()->resources;
        $resource = $this->getConfig('resource');
        if ($resource === null) {
            $this->resource = $resources->defaultResource()->identifier;

            return;
        }
        if (!is_string($resource) || $resources->get($resource) === null) {
            throw new InvalidArgumentException(sprintf(
                'The resource "%s" of the Token authenticator is not declared in OAuthServer.resources.',
                is_string($resource) ? $resource : get_debug_type($resource),
            ));
        }
        $this->resource = $resource;
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
