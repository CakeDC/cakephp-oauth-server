<?php
declare(strict_types=1);

use Cake\Cache\Cache;
use Cake\Core\Configure;
use Cake\Datasource\ConnectionManager;
use Cake\Utility\Security;
use Migrations\TestSuite\Migrator;

if (!defined('DS')) {
    define('DS', DIRECTORY_SEPARATOR);
}
$pluginRoot = dirname(__DIR__);
$appDir = getenv('OAUTH_TEST_APP') ?: 'test_app';

define('ROOT', $pluginRoot . DS . 'tests' . DS . $appDir . DS);
define('APP_DIR', 'src');
define('APP', ROOT . 'src' . DS);
define('CONFIG', ROOT . 'config' . DS);
define('WWW_ROOT', ROOT . 'webroot' . DS);
define('TMP', ROOT . 'tmp' . DS);
define('LOGS', TMP . 'logs' . DS);
define('CACHE', TMP . 'cache' . DS);
define('CAKE_CORE_INCLUDE_PATH', $pluginRoot . DS . 'vendor' . DS . 'cakephp' . DS . 'cakephp');
define('CORE_PATH', CAKE_CORE_INCLUDE_PATH . DS);
define('CAKE', CORE_PATH . 'src' . DS);

require $pluginRoot . '/vendor/autoload.php';
require CORE_PATH . 'config' . DS . 'bootstrap.php';

date_default_timezone_set('UTC');
Configure::write('debug', true);
Configure::write('App', [
    'namespace' => $appDir === 'test_app' ? 'TestApp' : 'UsersTestApp',
    'encoding' => 'UTF-8',
    'defaultLocale' => 'en_US',
    'defaultTimezone' => 'UTC',
    'base' => false,
    'baseUrl' => false,
    'dir' => APP_DIR,
    'webroot' => 'webroot',
    'wwwRoot' => WWW_ROOT,
    'fullBaseUrl' => 'http://localhost',
    'paths' => [
        'plugins' => [ROOT . 'plugins' . DS],
        'templates' => [ROOT . 'templates' . DS],
        'locales' => [ROOT . 'resources' . DS . 'locales' . DS],
    ],
]);
Security::setSalt('cakephp-oauth-server-test-salt-cakephp-oauth-server-test-salt');
Cache::setConfig([
    '_cake_core_' => ['engine' => 'Array'],
    '_cake_translations_' => ['engine' => 'Array'],
    '_cake_model_' => ['engine' => 'Array'],
    '_cake_routes_' => ['engine' => 'Array'],
    'default' => ['engine' => 'Array'],
]);
ConnectionManager::setConfig('test', ['url' => getenv('DB_URL') ?: 'sqlite:///:memory:', 'timezone' => 'UTC']);
ConnectionManager::alias('test', 'default');

Configure::write('OAuthServer', [
    'resources' => [
        'http://localhost/mcp' => [
            'name' => 'Test MCP',
            'scopes' => [
                'content:read' => 'Read your posts',
                'content:write' => 'Edit drafts',
                'content:publish' => 'Publish posts',
            ],
            'implies' => ['content:publish' => ['content:write'], 'content:write' => ['content:read']],
            'defaultScopes' => ['content:read'],
        ],
        'http://localhost/api' => [
            'name' => 'Test API',
            'scopes' => ['api' => 'Use the API'],
            'defaultScopes' => ['api'],
        ],
    ],
    'tokenPrefix' => 'test',
    'userProvider' => ['table' => 'Users', 'finder' => 'active'],
    'cimd' => ['enabled' => false],
    // Rate limiting counts across tests in one process; the tests that check it switch it on.
    'rateLimit' => ['cache' => null],
]);

// Task 2 replaces this block once the plugin has migrations.
if (glob($pluginRoot . '/config/Migrations/*.php')) {
    (new Migrator())->runMany([['plugin' => 'CakeDC/OAuthServer'], []]);
}
