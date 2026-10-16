<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Identity;

use ArrayAccess;
use Authentication\IdentityInterface;
use BadMethodCallException;
use CakeDC\OAuth\Server\Token\ValidatedToken;

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
     * @inheritDoc
     */
    public function offsetExists(mixed $offset): bool
    {
        $data = $this->getOriginalData();

        return isset($data[$offset]);
    }

    /**
     * @inheritDoc
     */
    public function offsetGet(mixed $offset): mixed
    {
        $data = $this->getOriginalData();

        return $data[$offset] ?? null;
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
        return $this->offsetGet($name);
    }

    /**
     * Whether a field is set.
     */
    public function __isset(string $name): bool
    {
        return $this->offsetExists($name);
    }
}
