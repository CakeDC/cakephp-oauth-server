<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\I18n;

use Cake\I18n\I18n;
use Cake\I18n\MessagesFileLoader;
use Cake\I18n\Package;
use Cake\I18n\Parser\PoFileParser;
use Locale;

/**
 * Loads the plugin's `oauth_server` translation domain: the plugin's own `.po` file, overridden message by
 * message by the application's `resources/locales/<locale>/oauth_server.po` when it has one.
 *
 * Cake only loads a plugin's locale folder for a domain named after the plugin, so the plugin registers this
 * loader for its own domain.
 */
final class PluginMessagesLoader
{
    public const DOMAIN = 'oauth_server';

    /**
     * Registers the loader for the `oauth_server` domain.
     *
     * @return void
     */
    public static function register(): void
    {
        I18n::translators()->registerLoader(self::DOMAIN, new self());
    }

    /**
     * Builds the package of $locale.
     *
     * @param string $name The domain.
     * @param string $locale The locale.
     * @return \Cake\I18n\Package
     */
    public function __invoke(string $name, string $locale): Package
    {
        $messages = [];
        $parsed = Locale::parseLocale($locale);
        $language = $parsed['language'] ?? '';
        $candidates = array_unique(array_filter([$language, $locale]));
        // The language first, the specific locale over it.
        foreach ($candidates as $candidate) {
            $file = dirname(__DIR__, 2) . '/resources/locales/' . $candidate . '/' . self::DOMAIN . '.po';
            if (is_file($file)) {
                $messages = array_merge($messages, (new PoFileParser())->parse($file));
            }
        }
        $package = new Package('default');
        $package->setMessages($messages);

        $app = (new MessagesFileLoader(self::DOMAIN, $locale, 'po'))();
        if ($app instanceof Package) {
            $package->addMessages($app->getMessages());
        }

        return $package;
    }
}
