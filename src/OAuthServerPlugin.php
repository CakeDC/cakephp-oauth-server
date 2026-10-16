<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer;

use Cake\Console\CommandCollection;
use Cake\Core\BasePlugin;
use Cake\Core\ContainerInterface;
use Cake\Core\PluginApplicationInterface;
use Cake\Log\Engine\BaseLog;
use Cake\Log\Engine\FileLog;
use Cake\Log\Log;
use Cake\Routing\RouteBuilder;
use CakeDC\OAuth\Server\AuthorizationServer;
use CakeDC\OAuthServer\Command\OAuthCheckCommand;
use CakeDC\OAuthServer\Command\OAuthClientAddCommand;
use CakeDC\OAuthServer\Command\OAuthClientListCommand;
use CakeDC\OAuthServer\Command\OAuthClientRevokeCommand;
use CakeDC\OAuthServer\Command\OAuthPruneCommand;
use CakeDC\OAuthServer\Command\OAuthTokenRevokeCommand;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\I18n\PluginMessagesLoader;

/**
 * An OAuth 2.1 authorization server for CakePHP applications.
 */
class OAuthServerPlugin extends BasePlugin
{
    /**
     * @inheritDoc
     */
    public function bootstrap(PluginApplicationInterface $app): void
    {
        parent::bootstrap($app);
        $this->registerLogEngine();
        PluginMessagesLoader::register();
    }

    /**
     * Adds an `oauth` log file unless an engine already receives the `oauth` scope (listed or catch-all)
     * or `oauth` is taken. The skeleton's debug and error engines have no scopes, so they do not receive
     * scoped messages.
     *
     * @return void
     */
    private function registerLogEngine(): void
    {
        if (Log::getConfig('oauth') !== null) {
            return;
        }
        foreach (Log::configured() as $name) {
            $engine = Log::engine($name);
            $scopes = $engine instanceof BaseLog ? $engine->scopes() : null;
            // An empty list is the catch-all (BaseLog default): it receives every scope.
            if ($scopes === [] || is_array($scopes) && in_array('oauth', $scopes, true)) {
                return;
            }
        }
        Log::setConfig('oauth', [
            'className' => FileLog::class,
            'path' => LOGS,
            'file' => 'oauth',
            'scopes' => ['oauth'],
        ]);
    }

    /**
     * Makes the server available to type-hinted controller actions and commands.
     *
     * @param \Cake\Core\ContainerInterface $container The container.
     * @return void
     */
    public function services(ContainerInterface $container): void
    {
        $container->addShared(AuthorizationServer::class, static fn(): AuthorizationServer => OAuthServer::server());
    }

    /**
     * Connects the metadata document and the endpoints.
     *
     * An invalid issuer or route prefix fails here, at boot, with an error that names the setting, instead
     * of connecting routes that do not match the metadata document the server publishes.
     *
     * @param \Cake\Routing\RouteBuilder $routes The builder.
     * @return void
     * @throws \InvalidArgumentException For an invalid configuration.
     */
    public function routes(RouteBuilder $routes): void
    {
        $config = PluginConfig::fromConfigure();
        $defaults = ['plugin' => 'CakeDC/OAuthServer', 'controller' => 'OAuth'];
        $routes->connect($config->metadataPath(), $defaults + ['action' => 'metadata']);
        foreach (['authorize', 'token', 'register', 'revoke', 'introspect', 'connections'] as $action) {
            $routes->connect($config->routePrefix() . '/' . $action, $defaults + ['action' => $action]);
        }
    }

    /**
     * Registers the `oauth` commands.
     *
     * @param \Cake\Console\CommandCollection $commands The collection.
     * @return \Cake\Console\CommandCollection
     */
    public function console(CommandCollection $commands): CommandCollection
    {
        return $commands
            ->add('oauth client add', OAuthClientAddCommand::class)
            ->add('oauth client list', OAuthClientListCommand::class)
            ->add('oauth client revoke', OAuthClientRevokeCommand::class)
            ->add('oauth token revoke', OAuthTokenRevokeCommand::class)
            ->add('oauth prune', OAuthPruneCommand::class)
            ->add('oauth check', OAuthCheckCommand::class);
    }
}
