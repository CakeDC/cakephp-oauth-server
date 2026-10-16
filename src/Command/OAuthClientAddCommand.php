<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOptionParser;
use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\GrantType;
use CakeDC\OAuthServer\OAuthServer;
use InvalidArgumentException;

/**
 * `bin/cake oauth client add`: registers a client by hand.
 */
class OAuthClientAddCommand extends Command
{
    /**
     * @inheritDoc
     */
    public static function defaultName(): string
    {
        return 'oauth client add';
    }

    /**
     * @inheritDoc
     */
    protected function buildOptionParser(ConsoleOptionParser $parser): ConsoleOptionParser
    {
        return $parser
            ->setDescription('Registers an OAuth client by hand. A secret is shown once for confidential clients.')
            ->addArgument('name', ['help' => 'Display name of the client.', 'required' => true])
            ->addOption('redirect-uri', ['help' => 'A redirect URI (repeat for more).', 'multiple' => true])
            ->addOption('confidential', ['help' => 'Give the client a secret.', 'boolean' => true])
            ->addOption('grant', [
                'help' => 'authorization_code, refresh_token or client_credentials (repeat for more; '
                    . 'default: the first two).',
                'multiple' => true,
            ])
            ->addOption('scope', ['help' => 'An allowed scope (repeat for more; default: any).', 'multiple' => true])
            ->addOption('introspection', ['help' => 'Allow the client to introspect tokens.', 'boolean' => true])
            ->addOption('native', [
                'help' => 'A native application (loopback or private-scheme redirect URIs).',
                'boolean' => true,
            ]);
    }

    /**
     * @inheritDoc
     */
    public function execute(Arguments $args, ConsoleIo $io): int
    {
        // Multiple options are read from the full list: Cake 5.4's getOption() throws for them.
        $options = $args->getOptions();
        $grants = self::strings($options['grant'] ?? []);
        $scopes = self::strings($options['scope'] ?? []);
        try {
            $result = OAuthServer::server()->clientRegistrar()->create(
                (string)$args->getArgument('name'),
                self::strings($options['redirect-uri'] ?? []),
                (bool)($options['confidential'] ?? false),
                $grants === [] ? [GrantType::AUTHORIZATION_CODE, GrantType::REFRESH_TOKEN] : $grants,
                $scopes === [] ? null : $scopes,
                (bool)($options['introspection'] ?? false),
                $options['native'] ?? false ? ApplicationType::Native : ApplicationType::Web,
            );
        } catch (InvalidArgumentException $e) {
            $io->error($e->getMessage());

            return static::CODE_ERROR;
        }
        $io->out('client_id: ' . $result['client']->clientId);
        if ($result['secret'] !== null) {
            $io->out('client_secret: ' . $result['secret']);
            $io->warning('Store the secret now; it is not shown again.');
        }

        return static::CODE_SUCCESS;
    }

    /**
     * A list of strings from an option value.
     *
     * @param mixed $value The option value.
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        return array_values(array_map('strval', array_filter((array)$value, 'is_scalar')));
    }
}
