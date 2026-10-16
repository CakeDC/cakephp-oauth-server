<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer;

use Cake\Console\CommandCollection;
use Cake\Core\BasePlugin;
use Cake\Core\ContainerInterface;
use Cake\Core\Plugin;
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
use CakeDC\OAuthServer\Integration\UsersIntegration;

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
        if (Plugin::isLoaded('CakeDC/Users')) {
            // Never throws: an invalid setting makes the authenticator it registers refuse this server's tokens.
            UsersIntegration::apply();
        }
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
     * Never throws, on the web or the command line: with an invalid configuration the routes are connected where
     * the settings that can still be read put them (see PluginConfig::lenientRouting()), the endpoints answer 503
     * and log the reason, and the rest of the application and `bin/cake` keep working. The paths do not depend on
     * the secret, so a missing or weak `Security.salt` changes nothing here.
     *
     * @param \Cake\Routing\RouteBuilder $routes The builder.
     * @return void
     */
    public function routes(RouteBuilder $routes): void
    {
        $routing = PluginConfig::fromConfigure()->lenientRouting();
        $defaults = ['plugin' => 'CakeDC/OAuthServer', 'controller' => 'OAuth'];
        $routes->connect($routing['metadata'], $defaults + ['action' => 'metadata']);
        foreach (['authorize', 'token', 'register', 'revoke', 'introspect', 'connections'] as $action) {
            $routes->connect($routing['prefix'] . '/' . $action, $defaults + ['action' => $action]);
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
