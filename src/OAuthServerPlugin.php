<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer;

use Cake\Core\BasePlugin;
use Cake\Core\PluginApplicationInterface;
use Cake\Log\Engine\FileLog;
use Cake\Log\Log;

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
    }

    /**
     * Adds an `oauth` log file unless an engine already receives the `oauth` scope. The skeleton's
     * debug and error engines have no scopes, so they do not receive scoped messages.
     *
     * @return void
     */
    private function registerLogEngine(): void
    {
        foreach (Log::configured() as $name) {
            $scopes = Log::getConfig($name)['scopes'] ?? null;
            if (is_array($scopes) && in_array('oauth', $scopes, true)) {
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
}
