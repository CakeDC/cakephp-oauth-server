<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Identity;

use ArrayAccess;
use Authentication\AuthenticationServiceInterface;
use Authentication\IdentityInterface;
use Authorization\IdentityDecorator;
use BadMethodCallException;
use CakeDC\OAuth\Server\Token\ValidatedToken;
use Error;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The identity of a request authenticated with an OAuth token: behaves like the owner's own
 * identity and also carries the validated token.
 */
final class OAuthIdentity implements IdentityInterface
{
    /**
     * @param \CakeDC\OAuth\Server\Token\ValidatedToken $token The validated token.
     */
    public function __construct(private readonly ValidatedToken $token)
    {
    }

    /**
     * The validated token of a request authenticated with a token of this server, also behind
     * cakephp/authorization's IdentityDecorator; null otherwise.
     *
     * The identity attribute is the one the request's authentication service reports, so renaming it
     * does not hide the token.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request The request.
     * @param string|null $attribute Attribute to read when the request has no authentication service.
     * @return \CakeDC\OAuth\Server\Token\ValidatedToken|null
     */
    public static function fromRequest(ServerRequestInterface $request, ?string $attribute = null): ?ValidatedToken
    {
        $service = $request->getAttribute('authentication');
        $name = $service instanceof AuthenticationServiceInterface
            ? $service->getIdentityAttribute()
            : ($attribute ?? 'identity');
        $identity = $request->getAttribute($name);
        if ($identity instanceof self) {
            return $identity->getOAuthToken();
        }
        if (!$identity instanceof IdentityDecorator) {
            return null;
        }
        try {
            $token = $identity->__call('getOAuthToken', []);
        } catch (BadMethodCallException | Error) {
            return null;
        }

        return $token instanceof ValidatedToken ? $token : null;
    }

    /**
     * The validated token: owner, client, resource and scopes.
     */
    public function getOAuthToken(): ValidatedToken
    {
        return $this->token;
    }

    /**
     * Whether the token holds $scope right now.
     */
    public function hasScope(string $scope): bool
    {
        return $this->token->hasScope($scope);
    }

    /**
     * The owner's identifier.
     *
     * @return array<mixed>|string|int|null
     */
    public function getIdentifier(): array|string|int|null
    {
        $identity = $this->token->owner->identity;

        return $identity instanceof IdentityInterface ? $identity->getIdentifier() : $this->token->owner->subject;
    }

    /**
     * The owner's own identity data.
     *
     * @return \ArrayAccess<array-key, mixed>|array<array-key, mixed>
     */
    public function getOriginalData(): ArrayAccess|array
    {
        $identity = $this->token->owner->identity;
        if ($identity instanceof IdentityInterface) {
            return $identity->getOriginalData();
        }

        if ($identity instanceof ArrayAccess || is_array($identity)) {
            return $identity;
        }

        return ['id' => $this->token->owner->subject];
    }

    /**
     * A field of the owner's identity, through its field map when it has one.
     *
     * @param string $field The field.
     * @return mixed
     */
    public function get(string $field): mixed
    {
        $identity = $this->token->owner->identity;
        if ($identity instanceof IdentityInterface) {
            return $identity[$field];
        }
        $data = $this->getOriginalData();

        return $data[$field] ?? null;
    }

    /**
     * @inheritDoc
     */
    public function offsetExists(mixed $offset): bool
    {
        return $this->get((string)$offset) !== null;
    }

    /**
     * @inheritDoc
     */
    public function offsetGet(mixed $offset): mixed
    {
        return $this->get((string)$offset);
    }

    /**
     * @inheritDoc
     */
    public function offsetSet(mixed $offset, mixed $value): void
    {
        throw new BadMethodCallException('An OAuth identity is read-only.');
    }

    /**
     * @inheritDoc
     */
    public function offsetUnset(mixed $offset): void
    {
        throw new BadMethodCallException('An OAuth identity is read-only.');
    }

    /**
     * Property-style access to the identity's fields, like Authentication\Identity.
     */
    public function __get(string $name): mixed
    {
        return $this->get($name);
    }

    /**
     * Whether a field is set.
     */
    public function __isset(string $name): bool
    {
        return $this->offsetExists($name);
    }
}
