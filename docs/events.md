# Events

The plugin forwards the core's events to Cake's global event manager. The event name is `OAuthServer.`
plus the event class name with a lowercase first letter. The subject of the Cake event is the core event
object (also available as `$event->getData('event')`). Token values, client secrets and codes never appear
in an event.

| Cake event name | Core class (`CakeDC\OAuth\Server\Event`) | Fires when |
| --- | --- | --- |
| `OAuthServer.tokenIssued` | `TokenIssued` | A token is stored: access, refresh or personal |
| `OAuthServer.tokenRevoked` | `TokenRevoked` | Tokens were revoked (only when at least one changed) |
| `OAuthServer.consentGranted` | `ConsentGranted` | A person approved a client |
| `OAuthServer.clientRegistered` | `ClientRegistered` | A client was registered, dynamically or by hand (`oauth client add`) |
| `OAuthServer.refreshTokenReused` | `RefreshTokenReused` | A rotated refresh token was replayed outside the grace window |
| `OAuthServer.authorizationDenied` | `AuthorizationDenied` | An authorization request was refused (`not_allowed` or `user_denied`) |

The properties of each event, the `reason` values of `TokenRevoked` and when each event fires are in the
core's [events](https://github.com/CakeDC/oauth-server/blob/1.x/docs/events.md).

Metadata document clients are created on first use and do not fire `clientRegistered`.

## Listening

Register listeners where your application boots, for example in `Application::bootstrap()`:

```php
use Cake\Event\Event;
use Cake\Event\EventManager;

EventManager::instance()->on('OAuthServer.tokenIssued', function (Event $event): void {
    /** @var \CakeDC\OAuth\Server\Event\TokenIssued $issued */
    $issued = $event->getSubject();
    // $issued->token, $issued->client
});
```

A listener class that implements `EventListenerInterface` works too, see the next section.

## An audit log example

```php
// src/Event/OAuthAuditListener.php
namespace App\Event;

use Cake\Event\Event;
use Cake\Event\EventListenerInterface;
use Cake\Log\Log;
use Throwable;

class OAuthAuditListener implements EventListenerInterface
{
    public function implementedEvents(): array
    {
        return [
            'OAuthServer.consentGranted' => 'consentGranted',
            'OAuthServer.tokenIssued' => 'tokenIssued',
            'OAuthServer.tokenRevoked' => 'tokenRevoked',
            'OAuthServer.clientRegistered' => 'clientRegistered',
            'OAuthServer.refreshTokenReused' => 'refreshTokenReused',
            'OAuthServer.authorizationDenied' => 'authorizationDenied',
        ];
    }

    public function consentGranted(Event $event): void
    {
        $e = $event->getSubject();
        $this->audit('oauth.consent', [
            'subject' => $e->owner->subject,
            'client' => $e->client->clientId,
            'resource' => $e->consent->resource,
            'scopes' => $e->consent->scopes,
        ]);
    }

    public function tokenIssued(Event $event): void
    {
        $e = $event->getSubject();
        $this->audit('oauth.token_issued', [
            'type' => $e->token->type->value,
            'subject' => $e->token->subject,
            'client' => $e->client?->clientId,
            'resource' => $e->token->resource,
        ]);
    }

    public function tokenRevoked(Event $event): void
    {
        $e = $event->getSubject();
        $this->audit('oauth.token_revoked', [
            'reason' => $e->reason,
            'count' => $e->count,
            'subject' => $e->subject,
        ]);
    }

    public function clientRegistered(Event $event): void
    {
        $this->audit('oauth.client_registered', ['client' => $event->getSubject()->client->clientId]);
    }

    public function refreshTokenReused(Event $event): void
    {
        $e = $event->getSubject();
        $this->audit('oauth.refresh_reused', ['client' => $e->client->clientId, 'subject' => $e->token->subject]);
    }

    public function authorizationDenied(Event $event): void
    {
        $e = $event->getSubject();
        $this->audit('oauth.denied', [
            'client' => $e->client->clientId,
            'subject' => $e->owner->subject,
            'reason' => $e->reason,
        ]);
    }

    /**
     * @param string $message
     * @param array<string, mixed> $context
     */
    private function audit(string $message, array $context): void
    {
        try {
            Log::info($message . ' ' . json_encode($context), ['scope' => 'oauth_audit']);
        } catch (Throwable) {
            // Never let logging break authorization.
        }
    }
}
```

Register it in `Application::bootstrap()` with
`EventManager::instance()->on(new \App\Event\OAuthAuditListener());`. Give the `oauth_audit` scope its own log engine in `config/app.php`:

```php
'Log' => [
    'oauth_audit' => [
        'className' => 'Cake\Log\Engine\FileLog',
        'path' => LOGS,
        'file' => 'oauth_audit',
        'scopes' => ['oauth_audit'],
    ],
],
```

## Rules for listeners

- **Never throw.** The event fires inside the OAuth request. A throwing `clientRegistered` listener loses
  the one-time client secret, and a throwing `tokenIssued` listener loses the issued tokens. Catch
  everything, as above.
- Keep them fast; they run before the response is sent.
- Alert on a rising rate of `refreshTokenReused`, not on single events: a client refreshing the same token
  from two processes causes the same event.
- To act on an event (for example to revoke tokens), use the core's services:
  `OAuthServer::server()->tokenRevoker()`.
