<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Identity;

use Authentication\Identity;
use Cake\Datasource\EntityInterface;
use Cake\ORM\Locator\LocatorAwareTrait;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use InvalidArgumentException;
use UnexpectedValueException;

/**
 * People from an ORM table, looked up with a finder (for example `active`).
 */
final class OrmUserProvider implements UserProviderInterface
{
    use LocatorAwareTrait;

    /**
     * @param array<string, mixed> $config Settings (PluginConfig::userProvider()).
     */
    public function __construct(private readonly array $config)
    {
    }

    /**
     * @inheritDoc
     */
    public function findBySubject(string $subject): ?ResourceOwner
    {
        $table = $this->fetchTable((string)$this->config['table']);
        $key = $table->getPrimaryKey();
        if (!is_string($key)) {
            throw new InvalidArgumentException('The users table needs a single-column primary key.');
        }
        if (!$this->hasKeyShape($table->getSchema()->getColumnType($key), $subject)) {
            return null;
        }
        $entity = $table->find((string)$this->config['finder'])
            ->where([$table->aliasField($key) => $subject])
            ->first();
        if (!$entity instanceof EntityInterface) {
            return null;
        }
        // Subjects are compared exactly: a case-insensitive collation or a loose integer comparison
        // ('1abc' = 1) must not let another spelling resolve to this person.
        $stored = $entity->get($key);
        if (!is_scalar($stored) || (string)$stored !== $subject) {
            return null;
        }
        $field = $this->config['displayField'] ?? $table->getDisplayField();
        $name = is_string($field) ? $entity->get($field) : null;
        $display = is_scalar($name) && (string)$name !== '' ? (string)$name : $subject;

        return new ResourceOwner((string)$stored, $display, new Identity($entity));
    }

    /**
     * Whether $subject can be a value of a key column of this type (the ORM throws on others).
     *
     * @param string|null $type Column type.
     * @param string $subject The subject.
     * @return bool
     */
    private function hasKeyShape(?string $type, string $subject): bool
    {
        if (in_array($type, ['integer', 'biginteger', 'smallinteger', 'tinyinteger'], true)) {
            return preg_match('/\A[0-9]+\z/', $subject) === 1;
        }

        return true;
    }

    /**
     * @inheritDoc
     */
    public function canAuthorize(ResourceOwner $owner, Client $client, ProtectedResource $resource): bool
    {
        $callback = $this->config['canAuthorize'];

        if ($callback === null) {
            return true;
        }
        $result = $callback($owner->identity, $client, $resource);
        if (!is_bool($result)) {
            throw new UnexpectedValueException('OAuthServer.userProvider.canAuthorize must return a bool.');
        }

        return $result;
    }

    /**
     * @inheritDoc
     */
    public function scopesFor(ResourceOwner $owner, ProtectedResource $resource): ?array
    {
        $callback = $this->config['scopes'];
        if ($callback === null) {
            return null;
        }
        $scopes = $callback($owner->identity, $resource);

        if ($scopes === null) {
            return null;
        }
        if (!is_array($scopes) || !array_is_list($scopes) || array_filter($scopes, 'is_string') !== $scopes) {
            throw new UnexpectedValueException(
                'OAuthServer.userProvider.scopes must return null or a list of strings.',
            );
        }

        return $scopes;
    }

    /**
     * @inheritDoc
     */
    public function forClient(Client $client, ProtectedResource $resource): ?ResourceOwner
    {
        $callback = $this->config['forClient'];
        $identity = $callback === null ? null : $callback($client, $resource);
        if ($identity === null || $identity === false) {
            return null;
        }
        if ($identity instanceof ResourceOwner) {
            return $identity;
        }
        if (is_scalar($identity)) {
            throw new UnexpectedValueException(
                'OAuthServer.userProvider.forClient must return an identity, a ResourceOwner, null or false.',
            );
        }

        return new ResourceOwner($client->clientId, $client->name, $identity, SubjectType::Client);
    }
}
