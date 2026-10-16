<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Command;

use Cake\Command\Command;
use Cake\Console\Arguments;
use Cake\Console\ConsoleIo;
use Cake\Console\ConsoleOutput;
use CakeDC\OAuthServer\OAuthServer;
use DateTimeImmutable;

/**
 * `bin/cake oauth client list`.
 */
class OAuthClientListCommand extends Command
{
    /**
     * @inheritDoc
     */
    public static function defaultName(): string
    {
        return 'oauth client list';
    }

    /**
     * @inheritDoc
     */
    public function execute(Arguments $args, ConsoleIo $io): int
    {
        $date = fn(?DateTimeImmutable $value): string => $value === null ? '-' : $value->format('Y-m-d H:i');
        $rows = [['Client id', 'Name', 'Type', 'Authentication', 'Created', 'Last used', 'Revoked']];
        foreach (OAuthServer::server()->storage()->findClients() as $client) {
            $rows[] = [
                $client->clientId,
                $client->name,
                $client->type->value,
                $client->authMethod->value,
                $date($client->createdAt),
                $date($client->lastUsedAt),
                $date($client->revokedAt),
            ];
        }
        $io->setOutputAs(ConsoleOutput::RAW);
        $rows = array_map(fn(array $row): array => array_map(self::plain(...), $row), $rows);
        // Cake's Table helper interprets console tags (and throws on some), so draw the table as raw text.
        $widths = [];
        foreach ($rows as $row) {
            foreach ($row as $i => $cell) {
                $widths[$i] = max($widths[$i] ?? 0, mb_strlen($cell));
            }
        }
        $separator = '+' . implode('+', array_map(fn(int $w): string => str_repeat('-', $w + 2), $widths)) . '+';
        $io->out($separator);
        foreach ($rows as $n => $row) {
            $cells = [];
            foreach ($row as $i => $cell) {
                $cells[] = ' ' . $cell . str_repeat(' ', $widths[$i] - mb_strlen($cell)) . ' ';
            }
            $io->out('|' . implode('|', $cells) . '|');
            if ($n === 0) {
                $io->out($separator);
            }
        }
        $io->out($separator);

        return static::CODE_SUCCESS;
    }

    /**
     * A client-supplied value that is safe to print: control characters (escape sequences, newlines)
     * become "?", and the output is raw so console tags are not interpreted.
     *
     * @param string $value The value.
     * @return string
     */
    private static function plain(string $value): string
    {
        return (string)preg_replace('/[\x00-\x1F\x7F]/', '?', $value);
    }
}
