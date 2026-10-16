<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Log;

use Cake\Core\PluginApplicationInterface;
use Cake\Log\Engine\ArrayLog;
use Cake\Log\Log;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Log\CakeLogger;
use CakeDC\OAuthServer\OAuthServerPlugin;
use Psr\Log\InvalidArgumentException;
use RuntimeException;
use stdClass;

class CakeLoggerTest extends TestCase
{
    protected function tearDown(): void
    {
        foreach (['oauth_test', 'debug', 'error', 'oauth'] as $name) {
            Log::drop($name);
        }
        parent::tearDown();
    }

    private function lines(string $name): string
    {
        $engine = Log::engine($name);
        $this->assertInstanceOf(ArrayLog::class, $engine);

        return implode("\n", $engine->read());
    }

    public function testWritesWithTheOauthScope(): void
    {
        Log::setConfig('oauth_test', ['className' => ArrayLog::class, 'scopes' => ['oauth']]);

        (new CakeLogger())->error('OAuth endpoint failed: {message}', ['message' => 'boom']);

        $this->assertStringContainsString('OAuth endpoint failed: boom', $this->lines('oauth_test'));
    }

    public function testAppendsTheExceptionClassAndLocationOnly(): void
    {
        Log::setConfig('oauth_test', ['className' => ArrayLog::class, 'scopes' => ['oauth']]);
        $exception = new RuntimeException('secret-detail');

        (new CakeLogger())->error('failed {message}', ['message' => 'x', 'exception' => $exception]);

        $text = $this->lines('oauth_test');
        $this->assertStringContainsString(
            RuntimeException::class . ' in ' . $exception->getFile() . ':' . $exception->getLine(),
            $text,
        );
        $this->assertStringNotContainsString('secret-detail', $text);
    }

    public function testNeverDumpsNonScalarContext(): void
    {
        Log::setConfig('oauth_test', ['className' => ArrayLog::class, 'scopes' => ['oauth']]);

        (new CakeLogger())->warning('see {request} {list}', ['request' => new stdClass(), 'list' => ['code' => 'abc123']]);

        $text = $this->lines('oauth_test');
        $this->assertStringContainsString('see {request} {list}', $text);
        $this->assertStringNotContainsString('abc123', $text);
    }

    public function testUnknownLevelIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        (new CakeLogger())->log('loud', 'x');
    }

    public function testPluginAddsAnOauthEngineWhenNoneReceivesTheScope(): void
    {
        Log::drop('debug');
        Log::drop('error');
        Log::setConfig('debug', ['className' => ArrayLog::class, 'levels' => ['notice', 'info', 'debug'], 'scopes' => null]);
        Log::setConfig('error', ['className' => ArrayLog::class, 'levels' => ['warning', 'error'], 'scopes' => null]);

        (new OAuthServerPlugin())->bootstrap($this->createStub(PluginApplicationInterface::class));
        (new CakeLogger())->error('endpoint failed');

        $config = Log::getConfig('oauth');
        $this->assertSame(['oauth'], $config['scopes']);
        $this->assertSame('oauth', $config['file']);
        $this->assertSame('', $this->lines('error'));
        Log::drop('oauth');
    }

    public function testPluginKeepsAnExistingEngineForTheScope(): void
    {
        Log::setConfig('oauth_test', ['className' => ArrayLog::class, 'scopes' => ['oauth']]);

        (new OAuthServerPlugin())->bootstrap($this->createStub(PluginApplicationInterface::class));

        $this->assertNull(Log::getConfig('oauth'));
    }

    public function testPluginLeavesAnExistingOauthEngineAlone(): void
    {
        Log::setConfig('oauth', ['className' => ArrayLog::class, 'scopes' => ['other']]);

        (new OAuthServerPlugin())->bootstrap($this->createStub(PluginApplicationInterface::class));

        $this->assertSame(ArrayLog::class, Log::getConfig('oauth')['className']);
    }

    public function testACatchAllEngineAlreadyReceivesTheScope(): void
    {
        Log::setConfig('oauth_test', ['className' => ArrayLog::class, 'scopes' => []]);

        (new OAuthServerPlugin())->bootstrap($this->createStub(PluginApplicationInterface::class));
        (new CakeLogger())->error('endpoint failed');

        $this->assertNull(Log::getConfig('oauth'));
        $this->assertStringContainsString('endpoint failed', $this->lines('oauth_test'));
    }
}
