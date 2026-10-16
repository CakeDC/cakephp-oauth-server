<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Identity;

use ArrayAccess;
use Authentication\AuthenticationServiceInterface;
use Authentication\Authenticator\ImpersonationInterface;
use Authentication\Authenticator\StatelessInterface;
use Authentication\IdentityInterface;
use Cake\Http\Response;
use Cake\Routing\Router;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Owner\UserContextInterface;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The person signed in with the application's own browser login (session, cakedc/users, ...).
 *
 * Identities that did not come from a browser session login are never accepted: a bearer token or
 * HTTP Basic credentials must not approve clients or create tokens.
 */
final class SessionUserContext implements UserContextInterface
{
    /**
     * @param \CakeDC\OAuth\Server\Owner\UserProviderInterface $users Reloads people, so inactive ones are refused.
     * @param array<string, mixed>|string $loginUrl Login page, as for Router::url().
     * @param string $redirectParam Query parameter the login reads the return URL from.
     * @param string $identityAttribute Request attribute holding the identity.
     */
    public function __construct(
        private readonly UserProviderInterface $users,
        private readonly string|array $loginUrl,
        private readonly string $redirectParam = 'redirect',
        private readonly string $identityAttribute = 'identity',
    ) {
    }

    /**
     * @inheritDoc
     */
    public function currentOwner(ServerRequestInterface $request): ?ResourceOwner
    {
        if ($this->isNotBrowserLogin($request)) {
            return null;
        }
        $service = $request->getAttribute('authentication');
        $attribute = $service instanceof AuthenticationServiceInterface
            ? $service->getIdentityAttribute()
            : $this->identityAttribute;
        $identity = $request->getAttribute($attribute);
        $subject = match (true) {
            $identity instanceof IdentityInterface => $identity->getIdentifier(),
            $identity instanceof ArrayAccess, is_array($identity) => $identity['id'] ?? null,
            default => null,
        };
        if (!is_int($subject) && !is_string($subject) || (string)$subject === '') {
            return null;
        }
        $owner = $this->users->findBySubject((string)$subject);

        return $owner !== null && $owner->type === SubjectType::User ? $owner : null;
    }

    /**
     * Whether the identity of the request was not established by a browser session login.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @return bool
     */
    private function isNotBrowserLogin(ServerRequestInterface $request): bool
    {
        $service = $request->getAttribute('authentication');
        if ($service instanceof AuthenticationServiceInterface) {
            $provider = $service->getAuthenticationProvider();
            if ($provider instanceof StatelessInterface) {
                return true;
            }
            if ($provider instanceof ImpersonationInterface && $provider->isImpersonating($request)) {
                return true;
            }
        }

        // A bearer token (also behind cakephp/authorization's IdentityDecorator) is never a person's login.
        return OAuthIdentity::fromRequest($request, $this->identityAttribute) !== null;
    }

    /**
     * @inheritDoc
     */
    public function loginResponse(ServerRequestInterface $request, string $returnTo): ResponseInterface
    {
        $login = $this->loginUrl;
        if (is_array($login) && !isset($login['_name'])) {
            // Router::url() would fill plugin and prefix from the current (plugin) request.
            $login += ['plugin' => false, 'prefix' => false];
        }
        $url = Router::url($login);
        $query = http_build_query([$this->redirectParam => $returnTo], '', '&', PHP_QUERY_RFC3986);

        return (new Response())
            ->withStatus(302)
            ->withHeader('Location', $url . (str_contains($url, '?') ? '&' : '?') . $query);
    }
}
