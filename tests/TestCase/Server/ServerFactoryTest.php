<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Server;

use Cake\Http\ServerRequest;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\Config\PluginConfig;
use CakeDC\OAuthServer\Identity\OrmUserProvider;
use CakeDC\OAuthServer\Server\ServerFactory;
use CakeDC\OAuthServer\Test\Support\StubUserProvider;
use InvalidArgumentException;
use stdClass;

class ServerFactoryTest extends TestCase
{
    /**
     * @param mixed $className The userProvider className setting.
     * @return \CakeDC\OAuthServer\Server\ServerFactory
     */
    private function factory(mixed $className): ServerFactory
    {
        $settings = $className === null ? [] : ['className' => $className, 'table' => 'People'];

        return new ServerFactory(new PluginConfig(['userProvider' => $settings]));
    }

    /**
     * @return void
     */
    public function testTheDefaultProviderIsTheOrmOne(): void
    {
        $this->assertInstanceOf(OrmUserProvider::class, $this->factory(null)->userProvider());
    }

    /**
     * @return void
     */
    public function testAnInstanceIsUsedAsIs(): void
    {
        $instance = new StubUserProvider();

        $this->assertSame($instance, $this->factory($instance)->userProvider());
    }

    /**
     * @return void
     */
    public function testACustomClassIsBuiltWithTheSettings(): void
    {
        $provider = $this->factory(StubUserProvider::class)->userProvider();

        $this->assertInstanceOf(StubUserProvider::class, $provider);
        $this->assertSame('People', $provider->config['table']);
    }

    /**
     * @return void
     */
    public function testAnInvalidClassFailsClearly(): void
    {
        foreach ([stdClass::class, 'No\\Such\\Class', 42] as $invalid) {
            try {
                $this->factory($invalid)->userProvider();
                $this->fail('Expected an exception');
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('OAuthServer.userProvider.className', $e->getMessage());
            }
        }
    }

    /**
     * @return void
     */
    public function testTheClientIpFallsBackToUnknown(): void
    {
        $this->assertSame('unknown', ServerFactory::clientIp(new ServerRequest()));
        $request = new ServerRequest(['environment' => ['REMOTE_ADDR' => '203.0.113.9']]);
        $this->assertSame('203.0.113.9', ServerFactory::clientIp($request));
    }
}
