<?php
declare(strict_types=1);

/**
 * Runs OrmStorage::prune() in a process (and a database connection) of its own, for PruneLockTest. It prints its
 * connection id first (`connection: <id>`), so the test can see when it waits on a lock, then the prune result
 * (`result: <json>`). The test reads the marked lines only: anything else on standard output (a deprecation that
 * PHP prints before this script runs, for example) is not mistaken for them. The database comes from
 * OAUTH_PRUNE_DB_URL, the clock from the first argument.
 */

use Cake\Database\Driver\Postgres;
use Cake\Datasource\ConnectionManager;
use CakeDC\OAuthServer\Storage\OrmStorage;

// Errors and deprecations (CakePHP 5.1 on PHP 8.5 with the lowest dependencies prints some) go to stderr.
ini_set('display_errors', 'stderr');

require dirname(__DIR__, 2) . '/vendor/autoload.php';

date_default_timezone_set('UTC');
ConnectionManager::setConfig('default', [
    'url' => (string)getenv('OAUTH_PRUNE_DB_URL'),
    'timezone' => 'UTC',
    'cacheMetadata' => false,
    'persistent' => false,
]);
/** @var \Cake\Database\Connection $connection */
$connection = ConnectionManager::get('default');
$id = $connection->getDriver() instanceof Postgres ? 'SELECT pg_backend_pid()' : 'SELECT CONNECTION_ID()';
fwrite(STDOUT, 'connection: ' . (string)$connection->execute($id)->fetchColumn(0) . "\n");
fflush(STDOUT);

$result = (new OrmStorage())->prune(new DateTimeImmutable($argv[1] ?? 'now'), 7 * 86400, 30 * 86400);
fwrite(STDOUT, 'result: ' . (string)json_encode([
    'codes' => $result->codes,
    'tokens' => $result->tokens,
    'clients' => $result->clients,
]) . "\n");
