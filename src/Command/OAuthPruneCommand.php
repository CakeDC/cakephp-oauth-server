<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use CakeDC\OAuthServer\OAuthServer;

/**
 * `bin/cake oauth prune`: run it from cron.
 */
class OAuthPruneCommand extends Command
{
    /**
     * @inheritDoc
     */
    public static function defaultName(): string
    {
        return 'oauth prune';
    }

    /**
     * @inheritDoc
     */
    public function execute(Arguments $args, ConsoleIo $io): int
    {
        $result = OAuthServer::server()->pruner()->prune();
        $io->out(
            sprintf('Deleted %d codes, %d tokens and %d clients.', $result->codes, $result->tokens, $result->clients),
        );

        return static::CODE_SUCCESS;
    }
}
