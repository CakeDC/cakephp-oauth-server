<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase;

use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Authenticator\OAuthServerTokenAuthenticator;
use CakeDC\OAuthServer\Authenticator\TokenAuthenticator;
use CakeDC\OAuthServer\Authenticator\UsersOneTimeTokenAuthenticator;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Database\Type\UtcDateTimeType;
use CakeDC\OAuthServer\Event\CakeEventDispatcher;
use CakeDC\OAuthServer\Http\RequestPaths;
use CakeDC\OAuthServer\I18n\PluginMessagesLoader;
use CakeDC\OAuthServer\Identity\OAuthIdentity;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use CakeDC\OAuthServer\Identity\SessionUserContext;
use CakeDC\OAuthServer\Integration\RbacPermissionsProvider;
use CakeDC\OAuthServer\Integration\UsersIntegration;
use CakeDC\OAuthServer\Log\CakeLogger;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\OAuthServerPlugin;
use CakeDC\OAuthServer\Server\ServerFactory;
use CakeDC\OAuthServer\Storage\OrmStorage;
use CakeDC\OAuthServer\View\CakeConnectionsRenderer;
use CakeDC\OAuthServer\View\CakeConsentRenderer;
use CakeDC\OAuthServer\View\CakeErrorPageRenderer;
use CakeDC\OAuthServer\View\CakeTemplateRenderer;
use CakeDC\OAuthServer\View\QuotedName;
use ReflectionClass;
use ReflectionMethod;

/**
 * The public API boundary before 1.0 is written in the docblocks.
 */
class PublicApiTest extends TestCase
{
    public function testInternalClassesAreMarked(): void
    {
        $internal = [
            PluginConfig::class, ServerFactory::class, CakeTemplateRenderer::class, CakeConnectionsRenderer::class,
            CakeConsentRenderer::class, CakeErrorPageRenderer::class, UsersIntegration::class,
            PluginMessagesLoader::class, UtcDateTimeType::class, RbacPermissionsProvider::class,
            CakeEventDispatcher::class, CakeLogger::class, RequestPaths::class, UsersOneTimeTokenAuthenticator::class,
        ];
        foreach ($internal as $class) {
            $this->assertStringContainsString('@internal', (string)(new ReflectionClass($class))->getDocComment(), $class);
        }
    }

    public function testPublicClassesAreNotMarked(): void
    {
        $public = [
            OAuthServerPlugin::class, OAuthServer::class, TokenAuthenticator::class,
            OAuthServerTokenAuthenticator::class, OAuthIdentity::class, OrmStorage::class, OrmUserProvider::class,
            SessionUserContext::class, QuotedName::class,
        ];
        foreach ($public as $class) {
            $this->assertStringNotContainsString('@internal', (string)(new ReflectionClass($class))->getDocComment(), $class);
        }
    }

    public function testTheResolverOfTheTokenAuthenticatorIsInternal(): void
    {
        $this->assertStringContainsString(
            '@internal',
            (string)(new ReflectionMethod(TokenAuthenticator::class, 'resolve'))->getDocComment(),
        );
    }

    public function testTwoStaticMethodsAreInternal(): void
    {
        foreach (['pageCsp', 'forRequest'] as $method) {
            $this->assertStringContainsString(
                '@internal',
                (string)(new ReflectionMethod(OAuthServer::class, $method))->getDocComment(),
                $method,
            );
        }
        foreach (['server', 'reset', 'csrfSkip', 'token', 'rbacPermissions'] as $method) {
            $this->assertStringNotContainsString(
                '@internal',
                (string)(new ReflectionMethod(OAuthServer::class, $method))->getDocComment(),
                $method,
            );
        }
    }
}
