<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Log;

use Cake\Log\Log;
use Psr\Log\AbstractLogger;
use Psr\Log\InvalidArgumentException;
use Stringable;
use Throwable;

/**
 * The core's logger, writing to Cake's log with the `oauth` scope.
 *
 * @internal
 */
final class CakeLogger extends AbstractLogger
{
    /**
     * @inheritDoc
     */
    public function log($level, string|Stringable $message, array $context = []): void
    {
        $levels = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];
        if (!is_string($level) || !in_array($level, $levels, true)) {
            throw new InvalidArgumentException('Unknown log level.');
        }
        $replace = [];
        foreach ($context as $key => $value) {
            if (is_scalar($value) || $value instanceof Stringable) {
                $replace['{' . $key . '}'] = (string)$value;
            }
        }
        $text = strtr((string)$message, $replace);
        $exception = $context['exception'] ?? null;
        if ($exception instanceof Throwable) {
            $text .= "\n" . $exception::class . ' in ' . $exception->getFile() . ':' . $exception->getLine();
        }
        Log::write($level, $text, ['scope' => ['oauth']]);
    }
}
