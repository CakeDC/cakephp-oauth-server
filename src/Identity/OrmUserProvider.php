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
        try {
            $entity = $table->find((string)$this->config['finder'])
                ->where([$table->aliasField($key) => $subject])
                ->first();
        } catch (InvalidArgumentException) {
            // The ORM refuses a value that is not of the key's type (for example '1abc' for an integer key).
            return null;
        }
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
     * @inheritDoc
     */
    public function canAuthorize(ResourceOwner $owner, Client $client, ProtectedResource $resource): bool
    {
        $callback = $this->config['canAuthorize'];

        return $callback === null || (bool)$callback($owner->identity, $client, $resource);
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

        return is_array($scopes) ? array_values(array_map('strval', $scopes)) : null;
    }

    /**
     * @inheritDoc
     */
    public function forClient(Client $client, ProtectedResource $resource): ?ResourceOwner
    {
        $callback = $this->config['forClient'];
        $identity = $callback === null ? null : $callback($client, $resource);
        if ($identity === null || $identity instanceof ResourceOwner) {
            return $identity;
        }

        return new ResourceOwner($client->clientId, $client->name, $identity, SubjectType::Client);
    }
}
