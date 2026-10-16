<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use CakeDC\OAuthServer\OAuthServer;

/**
 * `bin/cake oauth token revoke --subject ID [--consents] | --client CLIENT_ID`.
 */
class OAuthTokenRevokeCommand extends Command
{
    /**
     * @inheritDoc
     */
    public static function defaultName(): string
    {
        return 'oauth token revoke';
    }

    /**
     * @inheritDoc
     */
    protected function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        return $parser
            ->setDescription('Revokes every token of a person or of a client.')
            ->addOption('subject', ['help' => 'The person\'s id.'])
            ->addOption('client', ['help' => 'The client id.'])
            ->addOption('consents', [
                'help' => 'With --subject, also delete the person\'s remembered consents, so no client skips '
                    . 'the consent page.',
                'boolean' => true,
            ]);
    }

    /**
     * @inheritDoc
     */
    public function execute(Arguments $args, ConsoleIo $io): int
    {
        $server = OAuthServer::server();
        $subject = $args->getOption('subject');
        $clientId = $args->getOption('client');
        $consents = (bool)$args->getOption('consents');
        $subject = is_string($subject) ? $subject : '';
        $clientId = is_string($clientId) ? $clientId : '';
        $deletedConsents = null;
        if ($subject !== '' && $clientId === '') {
            $count = $server->tokenRevoker()->revokeAllForSubject($subject);
            if ($consents) {
                $deletedConsents = $server->storage()->deleteConsentsBySubject($subject);
            }
        } elseif ($clientId !== '' && $subject === '' && !$consents) {
            $client = $server->storage()->findClientByClientId($clientId);
            if ($client === null) {
                $io->error('No client with that id.');

                return static::CODE_ERROR;
            }
            $count = $server->tokenRevoker()->revokeAllForClient($client);
        } else {
            $io->error('Pass either --subject (optionally with --consents) or --client.');

            return static::CODE_ERROR;
        }
        $io->out(sprintf('Revoked %d token(s).', $count));
        if ($deletedConsents !== null) {
            $io->out(sprintf('Deleted %d consent(s).', $deletedConsents));
        }

        return static::CODE_SUCCESS;
    }
}
