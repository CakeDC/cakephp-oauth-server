<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\I18n;

use Cake\I18n\Parser\PoFileParser;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/**
 * Every message of the `oauth_server` domain used by the templates and the code is in the template catalogue
 * and translated in the Spanish one, and the catalogues list nothing else.
 */
class TranslationsTest extends TestCase
{
    /**
     * The literal first argument of every `__d('oauth_server', ...)` call under templates/ and src/.
     *
     * @return list<string>
     */
    private static function usedMessages(): array
    {
        $root = dirname(__DIR__, 3);
        $messages = [];
        foreach (['templates', 'src'] as $directory) {
            $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/' . $directory));
            foreach ($files as $file) {
                if ($file->isFile() && $file->getExtension() === 'php') {
                    $messages = array_merge($messages, self::messagesIn((string)file_get_contents($file->getPathname())));
                }
            }
        }

        return array_values(array_unique($messages));
    }

    /**
     * @param string $code PHP source.
     * @return list<string>
     */
    private static function messagesIn(string $code): array
    {
        $tokens = array_values(array_filter(
            token_get_all($code),
            fn(array|string $token): bool => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT], true),
        ));
        $messages = [];
        foreach ($tokens as $i => $token) {
            if (!is_array($token) || $token[0] !== T_STRING || $token[1] !== '__d') {
                continue;
            }
            $domain = $tokens[$i + 2] ?? null;
            if (!is_array($domain) || $domain[0] !== T_CONSTANT_ENCAPSED_STRING || $domain[1] !== "'oauth_server'") {
                continue;
            }
            // The message: string literals joined with dots, up to the next comma or parenthesis.
            $message = '';
            for ($j = $i + 4; isset($tokens[$j]); $j++) {
                $part = $tokens[$j];
                if (is_array($part) && $part[0] === T_CONSTANT_ENCAPSED_STRING) {
                    $message .= stripcslashes(substr($part[1], 1, -1));
                } elseif ($part !== '.') {
                    break;
                }
            }
            $messages[] = $message;
        }

        return $messages;
    }

    /**
     * @param string $file A catalogue.
     * @return array<string, mixed>
     */
    private static function catalogue(string $file): array
    {
        $messages = (new PoFileParser())->parse(dirname(__DIR__, 3) . '/resources/locales/' . $file);
        unset($messages['']);

        return $messages;
    }

    public function testTheParserFindsTheMessages(): void
    {
        $used = self::usedMessages();

        $this->assertContains('Authorize {0}', $used);
        $this->assertContains(
            'Only continue if you just started this from an application on this computer: '
            . 'any program on this computer can use this address.',
            $used,
        );
    }

    public function testEveryMessageIsInBothCatalogues(): void
    {
        $template = self::catalogue('oauth_server.pot');
        $spanish = self::catalogue('es/oauth_server.po');
        foreach (self::usedMessages() as $message) {
            $this->assertArrayHasKey($message, $template, 'Missing in oauth_server.pot: ' . $message);
            $this->assertArrayHasKey($message, $spanish, 'Missing in es/oauth_server.po: ' . $message);
            $translation = $spanish[$message]['_context'][''] ?? $spanish[$message];
            $this->assertIsString($translation);
            $this->assertNotSame('', $translation, 'Not translated: ' . $message);
            // A placeholder of the source is in its translation.
            preg_match_all('/\{\d+\}/', $message, $placeholders);
            foreach ($placeholders[0] as $placeholder) {
                $this->assertStringContainsString($placeholder, $translation, $message);
            }
        }
    }

    public function testTheCataloguesListOnlyMessagesInUse(): void
    {
        $used = self::usedMessages();
        sort($used);
        $template = array_map('strval', array_keys(self::catalogue('oauth_server.pot')));
        $spanish = array_map('strval', array_keys(self::catalogue('es/oauth_server.po')));
        sort($template);
        sort($spanish);

        $this->assertSame($used, $template);
        $this->assertSame($used, $spanish);
    }
}
