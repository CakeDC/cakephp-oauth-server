<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Event;

use Cake\Event\Event;
use Cake\Event\EventManager;
use Psr\EventDispatcher\EventDispatcherInterface;
use ReflectionClass;

/**
 * Sends the core's events to Cake's global event manager as `OAuthServer.<eventName>`; the core
 * event is the subject and the `event` data.
 *
 * Listeners must not throw: a throwing listener loses a one-time client secret or the issued tokens.
 *
 * @internal
 */
final class CakeEventDispatcher implements EventDispatcherInterface
{
    /**
     * @inheritDoc
     */
    public function dispatch(object $event): object
    {
        $short = (new ReflectionClass($event))->getShortName();
        EventManager::instance()->dispatch(new Event('OAuthServer.' . lcfirst($short), $event, ['event' => $event]));

        return $event;
    }
}
