<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Log;

use Cake\Log\Engine\ArrayLog;
use Cake\Log\Log;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Log\CakeLogger;

class CakeLoggerTest extends TestCase
{
    public function testWritesWithTheOauthScope(): void
    {
        Log::setConfig('oauth_test', ['className' => ArrayLog::class, 'scopes' => ['oauth']]);

        (new CakeLogger())->error('OAuth endpoint failed: {message}', ['message' => 'boom']);

        $engine = Log::engine('oauth_test');
        $this->assertInstanceOf(ArrayLog::class, $engine);
        $this->assertStringContainsString('OAuth endpoint failed: boom', implode("\n", $engine->read()));
        Log::drop('oauth_test');
    }
}
