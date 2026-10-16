<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\TestSuite;

use ArrayAccess;
use Authentication\IdentityInterface;
use Cake\Datasource\EntityInterface;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Server\ServerFactory;
use InvalidArgumentException;
use LogicException;

/**
 * Issues tokens in tests that use IntegrationTestTrait, without going through the OAuth flow.
 */
trait OAuthTestTrait
{
    /**
     * A personal token for $identity, valid for a day, built through the public connection service.
     *
     * @param mixed $identity An id, an identity, an entity or an array with `id`.
     * @param list<string> $scopes Scopes; the resource's default scopes when empty.
     * @param string|null $resource Resource identifier; the default resource when null.
     * @return string
     * @throws \LogicException When personal tokens are disabled.
     * @throws \InvalidArgumentException For an unknown resource, an unknown or inactive identity, or
     *   scopes the identity may not hold.
     */
    protected function oauthTokenFor(mixed $identity, array $scopes = [], ?string $resource = null): string
    {
        $config = PluginConfig::fromConfigure();
        $server = OAuthServer::server();
        if (!$server->config()->personalTokens) {
            throw new LogicException(
                'OAuthTestTrait issues personal tokens, but "OAuthServer.personalTokens" is false. ' .
                'Enable personal tokens in the test configuration to use it.',
            );
        }
        $resources = $server->config()->resources;
        $target = $resource === null ? $resources->defaultResource() : $resources->get($resource);
        if ($target === null) {
            throw new InvalidArgumentException(sprintf('The resource "%s" is not declared.', (string)$resource));
        }
        $subject = match (true) {
            $identity instanceof IdentityInterface => $identity->getIdentifier(),
            $identity instanceof EntityInterface => $identity->get('id'),
            $identity instanceof ArrayAccess, is_array($identity) => $identity['id'] ?? null,
            default => $identity,
        };
        if (!is_scalar($subject) || (string)$subject === '') {
            throw new InvalidArgumentException('Cannot tell the id of this identity.');
        }
        $owner = (new ServerFactory($config))->userProvider()->findBySubject((string)$subject);
        if ($owner === null) {
            throw new InvalidArgumentException(
                sprintf('No active person with id "%s" is known to the user provider.', (string)$subject),
            );
        }

        try {
            return $server->connectionService()->createPersonalToken(
                $owner,
                'test',
                $target->identifier,
                $scopes === [] ? $target->defaultScopes : $scopes,
                1,
            )['value'];
        } catch (OAuthException $e) {
            throw new InvalidArgumentException(
                sprintf('Cannot issue a test token for "%s": %s', (string)$subject, $e->getMessage()),
                0,
                $e,
            );
        }
    }

    /**
     * Sends $token as the bearer token of the next request.
     *
     * @param string $token The token.
     * @return void
     */
    protected function withOAuthToken(string $token): void
    {
        $this->configRequest(['headers' => ['Authorization' => 'Bearer ' . $token]]);
    }

    /**
     * oauthTokenFor() and withOAuthToken() in one call; returns the token.
     *
     * @param mixed $identity An id, an identity, an entity or an array with `id`.
     * @param list<string> $scopes Scopes.
     * @param string|null $resource Resource identifier.
     * @return string
     */
    protected function actAsOAuth(mixed $identity, array $scopes = [], ?string $resource = null): string
    {
        $token = $this->oauthTokenFor($identity, $scopes, $resource);
        $this->withOAuthToken($token);

        return $token;
    }
}
