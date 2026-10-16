<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\View;

/**
 * Prints a name that anyone can choose (a self-registered client's) inside a translated sentence, with its boundary
 * drawn in markup: the name goes in a `<q>` element, so no character in it can close a quote and go on as if the
 * server were speaking. The consent and connections templates use it; so should a template of yours that shows
 * `ConsentView::declaredName()` or a dynamic client's name.
 */
final class QuotedName
{
    /**
     * The placeholder of the name in the message.
     */
    public const PLACEHOLDER = '{0}';

    /**
     * $template escaped, with $name escaped inside a `<q>` element at its `{0}` placeholder. Translate the message
     * with the placeholder kept, for example
     * `QuotedName::html(__d('oauth_server', 'It calls itself {0}. Anyone can choose that name.', '{0}'), $name)`.
     * When a translation lacks the placeholder the name is appended in its own `<q>` element, never dropped.
     *
     * @param string $template The translated message with a `{0}` placeholder.
     * @param string $name The name.
     * @return string HTML.
     */
    public static function html(string $template, string $name): string
    {
        $parts = explode(self::PLACEHOLDER, $template, 2);
        $quoted = '<q>' . self::escape($name) . '</q>';

        return count($parts) === 2
            ? self::escape($parts[0]) . $quoted . self::escape($parts[1])
            : self::escape($template) . ' ' . $quoted;
    }

    /**
     * @param string $text Text.
     * @return string
     */
    private static function escape(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
