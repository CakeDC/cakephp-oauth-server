#!/usr/bin/php -q
<?php
declare(strict_types=1);

use Cake\Console\CommandRunner;
use TestApp\Application;

require dirname(__DIR__, 2) . '/bootstrap.php';

exit((new CommandRunner(new Application(CONFIG), 'cake'))->run($argv));
