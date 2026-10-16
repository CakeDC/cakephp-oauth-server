<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Event;

use Cake\Event\Event;
use Cake\Event\EventManager;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Sends the core's events to Cake's global event manager as `OAuthServer.<eventName>`; the core
 * event is the subject and the `event` data.
 */
final class CakeEventDispatcher implements EventDispatcherInterface
{
    /**
     * @inheritDoc
     */
    public function dispatch(object $event): object
    {
        $class = $event::class;
        $short = substr($class, (int)strrpos($class, '\\') + 1);
        EventManager::instance()->dispatch(new Event('OAuthServer.' . lcfirst($short), $event, ['event' => $event]));

        return $event;
    }
}
