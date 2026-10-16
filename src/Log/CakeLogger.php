<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Log;

use Cake\Log\Log;
use Psr\Log\AbstractLogger;
use Stringable;
use Throwable;

/**
 * The core's logger, writing to Cake's log with the `oauth` scope.
 */
final class CakeLogger extends AbstractLogger
{
    /**
     * @inheritDoc
     */
    public function log($level, string|Stringable $message, array $context = []): void
    {
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
        Log::write((string)$level, $text, ['scope' => ['oauth']]);
    }
}
