<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase;

use Authentication\Identifier\IdentifierCollection;
use Cake\Core\Configure;
use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Authenticator\TokenAuthenticator;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use ReflectionMethod;
use RuntimeException;
use SensitiveParameter;
use Throwable;

/**
 * A failure while a request is handled is logged with its exception, and loggers print the stack trace with the
 * arguments of every frame when `zend.exception_ignore_args` is off. Every plugin parameter that carries a token
 * or a secret is a `#[\SensitiveParameter]`, like the core's.
 */
class SecretsInTracesTest extends TestCase
{
    use OAuthTestTrait;

    private const SECRET = 'plugin-secret-0123456789-abcdefghij';
    private const INITIAL_ACCESS_TOKEN = 'initial-access-token-0123456789-abcdef';

    protected array $fixtures = Fixtures::ALL;

    /**
     * @var array{string|false, string|false}
     */
    private array $ini = [false, false];

    /**
     * @var array<string, mixed>
     */
    private array $settings = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->settings = (array)Configure::read('OAuthServer');
        $this->ini = [ini_get('zend.exception_ignore_args'), ini_get('zend.exception_string_param_max_len')];
        if (
            ini_set('zend.exception_ignore_args', '0') === false
            || ini_set('zend.exception_string_param_max_len', '1000000') === false
        ) {
            $this->markTestSkipped('The trace settings cannot be changed at run time here.');
        }
        OAuthServer::reset();
    }

    protected function tearDown(): void
    {
        if ($this->ini[0] !== false) {
            ini_set('zend.exception_ignore_args', $this->ini[0]);
        }
        if ($this->ini[1] !== false) {
            ini_set('zend.exception_string_param_max_len', $this->ini[1]);
        }
        Configure::write('OAuthServer', $this->settings);
        OAuthServer::reset();
        parent::tearDown();
    }

    /**
     * @return array<string, array{class-string, string, string}>
     */
    public static function sensitiveParameters(): array
    {
        return [
            'the settings (secret, initialAccessToken)' => [PluginConfig::class, '__construct', 'settings'],
            'the secret of the core settings' => [PluginConfig::class, 'buildServerConfig', 'secret'],
            'the bearer token of a test request' => [OAuthTestTrait::class, 'withOAuthToken', 'token'],
        ];
    }

    /**
     * @param class-string $class The class or trait.
     * @param string $method The method.
     * @param string $parameter The parameter.
     * @return void
     */
    #[DataProvider('sensitiveParameters')]
    public function testParametersThatCarrySecretsAreSensitive(string $class, string $method, string $parameter): void
    {
        foreach ((new ReflectionMethod($class, $method))->getParameters() as $candidate) {
            if ($candidate->getName() === $parameter) {
                $this->assertNotSame([], $candidate->getAttributes(SensitiveParameter::class), "{$class}::{$method}");

                return;
            }
        }
        $this->fail("{$class}::{$method}() has no parameter \${$parameter}.");
    }

    public function testAConfigurationErrorDoesNotPutTheSecretsInTheTrace(): void
    {
        Configure::write('OAuthServer.secret', self::SECRET);
        Configure::write('OAuthServer.registration', ['mode' => 'token', 'initialAccessToken' => self::INITIAL_ACCESS_TOKEN]);
        Configure::write('OAuthServer.routePrefix', 'no-leading-slash');

        try {
            OAuthServer::server();
            $this->fail('The invalid route prefix was accepted.');
        } catch (Throwable $e) {
            $this->assertTraceHides($e, [self::SECRET, self::INITIAL_ACCESS_TOKEN]);
        }
    }

    public function testAFailingDatabaseDoesNotPutTheBearerTokenInTheTrace(): void
    {
        $token = $this->oauthTokenFor(1, [], 'http://localhost/api');
        $this->fetchTable('CakeDC/OAuthServer.OauthTokens')->getEventManager()->on('Model.beforeFind', function (): void {
            throw new RuntimeException('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away');
        });
        $request = (new ServerRequest(['url' => '/api/me']))->withHeader('Authorization', 'Bearer ' . $token);
        $authenticator = new TokenAuthenticator(new IdentifierCollection(), ['resource' => 'http://localhost/api']);

        try {
            $authenticator->authenticate($request);
            $this->fail('The storage failure did not surface.');
        } catch (RuntimeException $e) {
            $this->assertTraceHides($e, [$token]);
        }
    }

    /**
     * @param \Throwable $error The error.
     * @param list<string> $secrets What must not appear.
     * @return void
     */
    private function assertTraceHides(Throwable $error, array $secrets): void
    {
        $rendered = '';
        $arguments = [];
        for ($e = $error; $e !== null; $e = $e->getPrevious()) {
            $rendered .= $e->getTraceAsString() . "\n" . $e;
            foreach ($e->getTrace() as $frame) {
                $args = $frame['args'] ?? [];
                array_walk_recursive($args, function (mixed $value) use (&$arguments): void {
                    if (is_string($value)) {
                        $arguments[] = $value;
                    }
                });
            }
        }
        $this->assertStringContainsString('#1 ', $rendered, 'The trace is empty.');
        foreach ($secrets as $secret) {
            $this->assertStringNotContainsString($secret, $rendered);
            $this->assertStringNotContainsString(substr($secret, 0, 15), $rendered);
            foreach ($arguments as $argument) {
                $this->assertStringNotContainsString($secret, $argument);
            }
        }
    }
}
