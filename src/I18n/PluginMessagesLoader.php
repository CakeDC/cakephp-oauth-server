<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\I18n;

use Cake\I18n\I18n;
use Cake\I18n\MessagesFileLoader;
use Cake\I18n\Package;
use Cake\I18n\Parser\PoFileParser;
use Cake\I18n\TranslatorRegistry;
use Locale;
use ReflectionException;
use ReflectionProperty;

/**
 * Loads the plugin's `oauth_server` translation domain: the plugin's own `.po` file, overridden message by
 * message by the application's `resources/locales/<locale>/oauth_server.po` when it has one.
 *
 * Cake only loads a plugin's locale folder for a domain named after the plugin, so the plugin registers this
 * loader for its own domain.
 *
 * @internal
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
        // An application that registered its own loader for the domain keeps it.
        try {
            $loaders = (new ReflectionProperty(TranslatorRegistry::class, '_loaders'))->getValue(I18n::translators());
        } catch (ReflectionException) {
            // Cake renamed the property: register the plugin loader, which already merges the app's files.
            $loaders = null;
        }
        if (is_array($loaders) && isset($loaders[self::DOMAIN]) && !$loaders[self::DOMAIN] instanceof self) {
            return;
        }
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

        // The application's override files, .mo before .po as Cake's own loader does.
        foreach (['mo', 'po'] as $extension) {
            $app = (new MessagesFileLoader(self::DOMAIN, $locale, $extension))();
            if ($app instanceof Package) {
                $package->addMessages($app->getMessages());
                break;
            }
        }

        return $package;
    }
}
