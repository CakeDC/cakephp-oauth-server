<?php
declare(strict_types=1);

/**
 * Prepended to the prune worker by PruneLockTest: a line on standard output before the worker writes anything,
 * like the deprecation CakePHP 5.1 prints on PHP 8.5 with the lowest dependencies.
 */

echo "Deprecated: a notice printed before the worker's own output\n";
