<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Event;

use Cake\Event\EventInterface;
use Cake\Event\EventManager;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Event\TokenRevoked;
use CakeDC\OAuthServer\Event\CakeEventDispatcher;

class CakeEventDispatcherTest extends TestCase
{
    public function testDispatchesNamedCakeEvents(): void
    {
        $seen = [];
        EventManager::instance()->on('OAuthServer.tokenRevoked', function (EventInterface $event) use (&$seen): void {
            $seen[] = $event;
        });
        $core = new TokenRevoked('client', 2, familyId: 'f');

        $this->assertSame($core, (new CakeEventDispatcher())->dispatch($core));

        $this->assertCount(1, $seen);
        $this->assertSame($core, $seen[0]->getSubject());
        $this->assertSame($core, $seen[0]->getData('event'));
    }
}
