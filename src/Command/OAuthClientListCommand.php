<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use CakeDC\OAuthServer\OAuthServer;
use DateTimeImmutable;

/**
 * `bin/cake oauth client list`.
 */
class OAuthClientListCommand extends Command
{
    /**
     * @inheritDoc
     */
    public static function defaultName(): string
    {
        return 'oauth client list';
    }

    /**
     * @inheritDoc
     */
    public function execute(Arguments $args, ConsoleIo $io): int
    {
        $date = fn(?DateTimeImmutable $value): string => $value === null ? '-' : $value->format('Y-m-d H:i');
        $rows = [['Client id', 'Name', 'Type', 'Authentication', 'Created', 'Last used', 'Revoked']];
        foreach (OAuthServer::server()->storage()->findClients() as $client) {
            $rows[] = [
                $client->clientId,
                $client->name,
                $client->type->value,
                $client->authMethod->value,
                $date($client->createdAt),
                $date($client->lastUsedAt),
                $date($client->revokedAt),
            ];
        }
        $io->helper('Table')->output($rows);

        return static::CODE_SUCCESS;
    }
}
