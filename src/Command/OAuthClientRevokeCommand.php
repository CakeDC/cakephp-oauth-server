<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use CakeDC\OAuthServer\OAuthServer;

/**
 * `bin/cake oauth client revoke <client_id>`.
 */
class OAuthClientRevokeCommand extends Command
{
    /**
     * @inheritDoc
     */
    public static function defaultName(): string
    {
        return 'oauth client revoke';
    }

    /**
     * @inheritDoc
     */
    protected function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        return $parser
            ->setDescription('Revokes a client and every token it holds.')
            ->addArgument('client_id', ['help' => 'The client id.', 'required' => true]);
    }

    /**
     * @inheritDoc
     */
    public function execute(Arguments $args, ConsoleIo $io): int
    {
        $server = OAuthServer::server();
        $client = $server->storage()->findClientByClientId((string)$args->getArgument('client_id'));
        if ($client === null) {
            $io->error('No client with that id.');

            return static::CODE_ERROR;
        }
        $server->storage()->saveClient($client->withRevokedAt($server->clock()->now()));
        $count = $server->tokenRevoker()->revokeAllForClient($client);
        $io->out(sprintf('Revoked the client and %d token(s).', $count));

        return static::CODE_SUCCESS;
    }
}
