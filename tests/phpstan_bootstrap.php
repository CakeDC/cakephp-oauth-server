<?php
declare(strict_types=1);

/**
 * Bootstrap for PHPStan, which only reads the code: the autoloader, CakePHP's global functions and the path
 * constants the plugin names. Unlike tests/bootstrap.php it connects to no database and runs no migration, so
 * an analysis leaves nothing behind.
 */

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';
require $root . '/vendor/cakephp/cakephp/src/functions.php';

$app = $root . DIRECTORY_SEPARATOR . 'tests' . DIRECTORY_SEPARATOR . 'test_app' . DIRECTORY_SEPARATOR;
$constants = [
    'DS' => DIRECTORY_SEPARATOR,
    'ROOT' => $app,
    'APP_DIR' => 'src',
    'APP' => $app . 'src' . DIRECTORY_SEPARATOR,
    'CONFIG' => $app . 'config' . DIRECTORY_SEPARATOR,
    'WWW_ROOT' => $app . 'webroot' . DIRECTORY_SEPARATOR,
    'TMP' => $app . 'tmp' . DIRECTORY_SEPARATOR,
    'LOGS' => $app . 'tmp' . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR,
    'CACHE' => $app . 'tmp' . DIRECTORY_SEPARATOR . 'cache' . DIRECTORY_SEPARATOR,
];
foreach ($constants as $name => $value) {
    if (!defined($name)) {
        define($name, $value);
    }
}
