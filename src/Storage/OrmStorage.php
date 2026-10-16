<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Storage;

use Cake\Datasource\EntityInterface;
use Cake\ORM\Locator\LocatorAwareTrait;
use Cake\ORM\Table;
use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Grant\AuthorizationCode;
use CakeDC\OAuth\Server\Grant\Consent;
use CakeDC\OAuth\Server\Maintenance\PruneResult;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Storage\StorageInterface;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenGenerator;
use CakeDC\OAuth\Server\Token\TokenType;
use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;

/**
 * The core storage on the plugin's ORM tables.
 *
 * Datetime columns are pinned to UTC by the tables' schema, so instants never depend on the application's
 * default timezone. The one-shot operations (consuming a code, marking a refresh token used, revoking) are
 * single conditional UPDATE statements whose affected row count decides the winner.
 */
final class OrmStorage implements StorageInterface
{
    use LocatorAwareTrait;

    /**
     * @inheritDoc
     */
    public function findClientByClientId(string $clientId): ?Client
    {
        $row = $this->clients()->find()->where(['client_id_hash' => TokenGenerator::hash($clientId)])->first();

        return $row instanceof EntityInterface ? $this->client($row) : null;
    }

    /**
     * @inheritDoc
     */
    public function findClientById(string $id): ?Client
    {
        $row = $this->clients()->find()->where(['id' => $id])->first();

        return $row instanceof EntityInterface ? $this->client($row) : null;
    }

    /**
     * @inheritDoc
     */
    public function saveClient(Client $client): void
    {
        $table = $this->clients();
        $row = $table->find()->where(['id' => $client->id])->first();
        $exists = $row instanceof EntityInterface;
        $data = [
            'client_id' => $client->clientId,
            'client_id_hash' => TokenGenerator::hash($client->clientId),
            'type' => $client->type->value,
            'application_type' => $client->applicationType->value,
            'name' => $client->name,
            'client_uri' => $client->clientUri,
            'logo_uri' => $client->logoUri,
            'redirect_uris' => $client->redirectUris,
            'grant_types' => $client->grantTypes,
            'scopes' => $client->scopes,
            'token_endpoint_auth_method' => $client->authMethod->value,
            'secret_hash' => $client->secretHash,
            'allow_introspection' => $client->allowIntrospection,
            'metadata' => $client->metadata,
            'metadata_fetched_at' => $client->metadataFetchedAt,
            'metadata_expires_at' => $client->metadataExpiresAt,
            'last_used_at' => $client->lastUsedAt,
            'modified' => new DateTimeImmutable('now', new DateTimeZone('UTC')),
        ];
        if ($exists) {
            // Revocation is sticky: an update never writes revoked_at from a copy, it only sets it once below.
            $entity = $row;
        } else {
            $entity = $table->newEmptyEntity();
            $data += ['id' => $client->id, 'created' => $client->createdAt, 'revoked_at' => $client->revokedAt];
        }
        $table->patchEntity($entity, $data, ['validate' => false, 'accessibleFields' => ['*' => true]]);
        $table->saveOrFail($entity, ['atomic' => false]);
        if ($exists && $client->revokedAt !== null) {
            $table->updateAll(
                ['revoked_at' => $client->revokedAt],
                ['id' => $client->id, 'revoked_at IS' => null],
            );
        }
    }

    /**
     * @inheritDoc
     */
    public function touchClient(string $id, DateTimeImmutable $at): void
    {
        $this->clients()->updateAll(['last_used_at' => $at], ['id' => $id]);
    }

    /**
     * @inheritDoc
     */
    public function findClients(?ClientType $type = null): array
    {
        $query = $this->clients()->find()->orderBy(['created' => 'ASC', 'id' => 'ASC']);
        if ($type !== null) {
            $query->where(['type' => $type->value]);
        }

        return array_values(array_map($this->client(...), $query->all()->toList()));
    }

    /**
     * @inheritDoc
     */
    public function saveCode(AuthorizationCode $code): void
    {
        $table = $this->codes();
        $table->saveOrFail($table->newEntity([
            'id' => $code->id,
            'code_hash' => $code->codeHash,
            'oauth_client_id' => $code->clientInternalId,
            'subject' => $code->subject,
            'redirect_uri' => $code->redirectUri,
            'resource' => $code->resource,
            'scopes' => $code->scopes,
            'code_challenge' => $code->codeChallenge,
            'family_id' => $code->familyId,
            'expires_at' => $code->expiresAt,
            'used_at' => $code->usedAt,
            'created' => $code->createdAt,
        ], ['validate' => false, 'accessibleFields' => ['*' => true]]), ['atomic' => false]);
    }

    /**
     * @inheritDoc
     */
    public function findCodeByHash(string $hash): ?AuthorizationCode
    {
        $row = $this->codes()->find()->where(['code_hash' => $hash])->first();
        if (!$row instanceof EntityInterface) {
            return null;
        }

        return new AuthorizationCode(
            id: (string)$row->get('id'),
            codeHash: (string)$row->get('code_hash'),
            clientInternalId: (string)$row->get('oauth_client_id'),
            subject: (string)$row->get('subject'),
            redirectUri: (string)$row->get('redirect_uri'),
            resource: (string)$row->get('resource'),
            scopes: self::strings($row->get('scopes')),
            codeChallenge: (string)$row->get('code_challenge'),
            expiresAt: self::date($row->get('expires_at')),
            createdAt: self::date($row->get('created')),
            usedAt: self::nullableDate($row->get('used_at')),
            familyId: $row->get('family_id') === null ? null : (string)$row->get('family_id'),
        );
    }

    /**
     * @inheritDoc
     */
    public function consumeCode(string $id, DateTimeImmutable $at, string $familyId): bool
    {
        $changed = $this->codes()->updateAll(
            ['used_at' => $at, 'family_id' => $familyId],
            ['id' => $id, 'used_at IS' => null],
        );

        return $changed === 1;
    }

    /**
     * @inheritDoc
     */
    public function saveToken(Token $token): void
    {
        $table = $this->tokens();
        $table->saveOrFail($table->newEntity([
            'id' => $token->id,
            'token_hash' => $token->tokenHash,
            'type' => $token->type->value,
            'family_id' => $token->familyId,
            'parent_id' => $token->parentId,
            'oauth_client_id' => $token->clientInternalId,
            'subject' => $token->subject,
            'subject_type' => $token->subjectType->value,
            'resource' => $token->resource,
            'scopes' => $token->scopes,
            'name' => $token->name,
            'expires_at' => $token->expiresAt,
            'used_at' => $token->usedAt,
            'revoked_at' => $token->revokedAt,
            'last_used_at' => $token->lastUsedAt,
            'family_started_at' => $token->familyStartedAt,
            'created' => $token->createdAt,
            'modified' => $token->createdAt,
        ], ['validate' => false, 'accessibleFields' => ['*' => true]]), ['atomic' => false]);
    }

    /**
     * @inheritDoc
     */
    public function findTokenByHash(string $hash): ?Token
    {
        $row = $this->tokens()->find()->where(['token_hash' => $hash])->first();

        return $row instanceof EntityInterface ? $this->token($row) : null;
    }

    /**
     * @inheritDoc
     */
    public function findTokenById(string $id): ?Token
    {
        $row = $this->tokens()->find()->where(['id' => $id])->first();

        return $row instanceof EntityInterface ? $this->token($row) : null;
    }

    /**
     * @inheritDoc
     */
    public function markTokenUsed(string $id, DateTimeImmutable $at): bool
    {
        $changed = $this->tokens()->updateAll(
            ['used_at' => $at, 'modified' => $at],
            ['id' => $id, 'used_at IS' => null, 'revoked_at IS' => null],
        );

        return $changed === 1;
    }

    /**
     * @inheritDoc
     */
    public function revokeToken(string $id, DateTimeImmutable $at): void
    {
        $this->revokeWhere(['id' => $id], $at);
    }

    /**
     * @inheritDoc
     */
    public function revokeTokenFamily(string $familyId, DateTimeImmutable $at): int
    {
        return $this->revokeWhere(['family_id' => $familyId], $at);
    }

    /**
     * @inheritDoc
     */
    public function revokeTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $at): int
    {
        return $this->revokeWhere(['subject' => $subject, 'subject_type' => $type->value], $at);
    }

    /**
     * @inheritDoc
     */
    public function revokeTokensByClient(string $clientInternalId, DateTimeImmutable $at): int
    {
        return $this->revokeWhere(['oauth_client_id' => $clientInternalId], $at);
    }

    /**
     * @inheritDoc
     */
    public function findTokensByFamily(string $familyId): array
    {
        $rows = $this->tokens()->find()
            ->where(['family_id' => $familyId])
            ->orderBy(['created' => 'ASC', 'id' => 'ASC']);

        return array_values(array_map($this->token(...), $rows->all()->toList()));
    }

    /**
     * @inheritDoc
     */
    public function findActiveTokensBySubject(string $subject, SubjectType $type, DateTimeImmutable $now): array
    {
        $rows = $this->tokens()->find()
            ->where([
                'subject' => $subject,
                'subject_type' => $type->value,
                'revoked_at IS' => null,
                'OR' => ['expires_at IS' => null, 'expires_at >' => $now],
            ])
            ->orderBy(['created' => 'ASC', 'id' => 'ASC']);

        return array_values(array_map($this->token(...), $rows->all()->toList()));
    }

    /**
     * @inheritDoc
     */
    public function touchToken(string $id, DateTimeImmutable $at): void
    {
        $this->tokens()->updateAll(['last_used_at' => $at], ['id' => $id]);
    }

    /**
     * @inheritDoc
     */
    public function findConsent(string $subject, string $clientInternalId, string $resource): ?Consent
    {
        $row = $this->consents()->find()->where([
            'subject' => $subject,
            'oauth_client_id' => $clientInternalId,
            'resource_hash' => hash('sha256', $resource),
        ])->first();

        return $row instanceof EntityInterface ? $this->consent($row) : null;
    }

    /**
     * @inheritDoc
     */
    public function findConsentsBySubject(string $subject): array
    {
        $rows = $this->consents()->find()
            ->where(['subject' => $subject])
            ->orderBy(['created' => 'ASC', 'id' => 'ASC']);

        return array_values(array_map($this->consent(...), $rows->all()->toList()));
    }

    /**
     * @inheritDoc
     */
    public function saveConsent(Consent $consent): void
    {
        $existing = $this->findConsent($consent->subject, $consent->clientInternalId, $consent->resource);
        $table = $this->consents();
        if ($existing !== null) {
            $table->updateAll(
                ['scopes' => $consent->scopes, 'modified' => $consent->modifiedAt],
                ['id' => $existing->id],
            );

            return;
        }
        $table->saveOrFail($table->newEntity([
            'id' => $consent->id,
            'subject' => $consent->subject,
            'oauth_client_id' => $consent->clientInternalId,
            'resource' => $consent->resource,
            'resource_hash' => hash('sha256', $consent->resource),
            'scopes' => $consent->scopes,
            'created' => $consent->createdAt,
            'modified' => $consent->modifiedAt,
        ], ['validate' => false, 'accessibleFields' => ['*' => true]]), ['atomic' => false]);
    }

    /**
     * @inheritDoc
     */
    public function deleteConsent(string $subject, string $clientInternalId, string $resource): void
    {
        $this->consents()->deleteAll([
            'subject' => $subject,
            'oauth_client_id' => $clientInternalId,
            'resource_hash' => hash('sha256', $resource),
        ]);
    }

    /**
     * @inheritDoc
     */
    public function deleteConsentsBySubject(string $subject): int
    {
        return $this->consents()->deleteAll(['subject' => $subject]);
    }

    /**
     * @inheritDoc
     */
    public function prune(DateTimeImmutable $now, int $retentionSeconds, int $unusedClientSeconds): PruneResult
    {
        $cutoff = Time::plus($now, -$retentionSeconds);
        $codes = $this->codes()->deleteAll(['expires_at <' => $now]);
        $tokens = $this->tokens()->deleteAll(['OR' => [
            ['revoked_at IS NOT' => null, 'revoked_at <' => $cutoff],
            ['expires_at IS NOT' => null, 'expires_at <' => $cutoff],
        ]]);
        $candidates = $this->clients()->find()
            ->select(['id'])
            ->where([
                'type IN' => [ClientType::Dynamic->value, ClientType::MetadataDocument->value],
                'revoked_at IS' => null,
                'created <' => Time::plus($now, -$unusedClientSeconds),
                'OR' => ['last_used_at IS' => null, 'last_used_at <' => $cutoff],
            ])
            ->all()
            ->extract('id')
            ->toList();
        $clients = 0;
        foreach ($candidates as $id) {
            $live = $this->tokens()->find()->where([
                'oauth_client_id' => $id,
                'revoked_at IS' => null,
                'OR' => ['expires_at IS' => null, 'expires_at >' => $now],
            ])->count();
            if ($live > 0) {
                continue;
            }
            $this->clients()->getConnection()->transactional(
                function () use ($id, &$tokens, &$codes, &$clients): void {
                    $tokens += $this->tokens()->deleteAll(['oauth_client_id' => $id]);
                    $codes += $this->codes()->deleteAll(['oauth_client_id' => $id]);
                    $this->consents()->deleteAll(['oauth_client_id' => $id]);
                    $clients += $this->clients()->deleteAll(['id' => $id]);
                },
            );
        }

        return new PruneResult($codes, $tokens, $clients);
    }

    /**
     * Revokes the live tokens matching $conditions and returns how many this call revoked.
     *
     * @param array<string, mixed> $conditions Conditions.
     * @param \DateTimeImmutable $at Revocation time.
     * @return int
     */
    private function revokeWhere(array $conditions, DateTimeImmutable $at): int
    {
        return $this->tokens()->updateAll(
            ['revoked_at' => $at, 'modified' => $at],
            $conditions + ['revoked_at IS' => null],
        );
    }

    /**
     * Builds a client from a row.
     *
     * @param \Cake\Datasource\EntityInterface $row The row.
     * @return \CakeDC\OAuth\Server\Client\Client
     */
    private function client(EntityInterface $row): Client
    {
        $metadata = $row->get('metadata');

        return new Client(
            id: (string)$row->get('id'),
            clientId: (string)$row->get('client_id'),
            type: ClientType::from((string)$row->get('type')),
            applicationType: ApplicationType::from((string)$row->get('application_type')),
            name: (string)$row->get('name'),
            redirectUris: self::strings($row->get('redirect_uris')),
            grantTypes: self::strings($row->get('grant_types')),
            authMethod: ClientAuthMethod::from((string)$row->get('token_endpoint_auth_method')),
            createdAt: self::date($row->get('created')),
            secretHash: $row->get('secret_hash') === null ? null : (string)$row->get('secret_hash'),
            scopes: $row->get('scopes') === null ? null : self::strings($row->get('scopes')),
            clientUri: $row->get('client_uri') === null ? null : (string)$row->get('client_uri'),
            logoUri: $row->get('logo_uri') === null ? null : (string)$row->get('logo_uri'),
            allowIntrospection: (bool)$row->get('allow_introspection'),
            metadata: is_array($metadata) ? self::stringKeys($metadata) : null,
            metadataFetchedAt: self::nullableDate($row->get('metadata_fetched_at')),
            metadataExpiresAt: self::nullableDate($row->get('metadata_expires_at')),
            lastUsedAt: self::nullableDate($row->get('last_used_at')),
            revokedAt: self::nullableDate($row->get('revoked_at')),
        );
    }

    /**
     * Builds a token from a row.
     *
     * @param \Cake\Datasource\EntityInterface $row The row.
     * @return \CakeDC\OAuth\Server\Token\Token
     */
    private function token(EntityInterface $row): Token
    {
        return new Token(
            id: (string)$row->get('id'),
            tokenHash: (string)$row->get('token_hash'),
            type: TokenType::from((string)$row->get('type')),
            familyId: (string)$row->get('family_id'),
            clientInternalId: $row->get('oauth_client_id') === null ? null : (string)$row->get('oauth_client_id'),
            subject: (string)$row->get('subject'),
            subjectType: SubjectType::from((string)$row->get('subject_type')),
            resource: (string)$row->get('resource'),
            scopes: self::strings($row->get('scopes')),
            createdAt: self::date($row->get('created')),
            expiresAt: self::nullableDate($row->get('expires_at')),
            name: $row->get('name') === null ? null : (string)$row->get('name'),
            parentId: $row->get('parent_id') === null ? null : (string)$row->get('parent_id'),
            usedAt: self::nullableDate($row->get('used_at')),
            revokedAt: self::nullableDate($row->get('revoked_at')),
            lastUsedAt: self::nullableDate($row->get('last_used_at')),
            familyStartedAt: self::nullableDate($row->get('family_started_at')),
        );
    }

    /**
     * Builds a consent from a row.
     *
     * @param \Cake\Datasource\EntityInterface $row The row.
     * @return \CakeDC\OAuth\Server\Grant\Consent
     */
    private function consent(EntityInterface $row): Consent
    {
        return new Consent(
            (string)$row->get('id'),
            (string)$row->get('subject'),
            (string)$row->get('oauth_client_id'),
            (string)$row->get('resource'),
            self::strings($row->get('scopes')),
            self::date($row->get('created')),
            self::date($row->get('modified')),
        );
    }

    /**
     * The clients table.
     *
     * @return \Cake\ORM\Table
     */
    private function clients(): Table
    {
        return $this->fetchTable('CakeDC/OAuthServer.OauthClients');
    }

    /**
     * The codes table.
     *
     * @return \Cake\ORM\Table
     */
    private function codes(): Table
    {
        return $this->fetchTable('CakeDC/OAuthServer.OauthAuthorizationCodes');
    }

    /**
     * The tokens table.
     *
     * @return \Cake\ORM\Table
     */
    private function tokens(): Table
    {
        return $this->fetchTable('CakeDC/OAuthServer.OauthTokens');
    }

    /**
     * The consents table.
     *
     * @return \Cake\ORM\Table
     */
    private function consents(): Table
    {
        return $this->fetchTable('CakeDC/OAuthServer.OauthConsents');
    }

    /**
     * A UTC DateTimeImmutable from a column value.
     *
     * @param mixed $value The column value.
     * @return \DateTimeImmutable
     */
    private static function date(mixed $value): DateTimeImmutable
    {
        if ($value instanceof DateTimeInterface) {
            return DateTimeImmutable::createFromInterface($value)->setTimezone(new DateTimeZone('UTC'));
        }

        return Time::parse((string)$value);
    }

    /**
     * A UTC DateTimeImmutable, or null.
     *
     * @param mixed $value The column value.
     * @return \DateTimeImmutable|null
     */
    private static function nullableDate(mixed $value): ?DateTimeImmutable
    {
        return $value === null ? null : self::date($value);
    }

    /**
     * A list of strings from a JSON column.
     *
     * @param mixed $value The column value.
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        if (is_string($value)) {
            $value = json_decode($value, true);
        }

        return is_array($value) ? array_values(array_map('strval', $value)) : [];
    }

    /**
     * The array with string keys.
     *
     * @param array<mixed> $value Value.
     * @return array<string, mixed>
     */
    private static function stringKeys(array $value): array
    {
        $result = [];
        foreach ($value as $key => $item) {
            $result[(string)$key] = $item;
        }

        return $result;
    }
}
