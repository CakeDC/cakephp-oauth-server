# Configuration

Everything lives under the `OAuthServer` key of `Configure`. Put it in `config/app_local.php` (or any file
you load into `Configure`):

```php
return [
    'OAuthServer' => [
        // ... the keys on this page
    ],
];
```

The plugin reads the configuration through `CakeDC\OAuthServer\Config\PluginConfig`. Types are strict:
numbers are integers (`3600`, not `'3600'`) and flags are `true` or `false`. An unknown key is an error that
names it, so a typo is found at once; it fails the OAuth parts only, see
[an invalid configuration](#an-invalid-configuration).

The keys come in two groups: **core keys**, handed to the core's `ServerConfig::fromArray()`, and
**plugin keys**, which only the plugin reads.

## Core keys

These are documented in full in the core's
[configuration](https://github.com/CakeDC/oauth-server/blob/1.x/docs/configuration.md). The summary:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `issuer` | string | `App.fullBaseUrl` | Canonical URL of the server. https only (http on localhost). No query, no trailing slash |
| `secret` | string | derived from `Security.salt` | At least 32 characters. Signs the consent and connections forms |
| `resources` | array | required | The resources tokens are issued for: `name`, `scopes`, `implies`, `defaultScopes` |
| `defaultResource` | string | first resource | Used when a client sends no `resource` |
| `routePrefix` | string | `/oauth` | Path of the endpoints below the issuer |
| `tokenPrefix` | string | `oauth` | Prefix of tokens (`<prefix>_at_...`); 1 to 16 lowercase letters or digits |
| `lifetimes` | array | see below | `code`, `access`, `refresh`, `family`, `personalMax`, `refreshReuseGrace` |
| `refreshTokens` | string | `always` | `always` or `offline_access` |
| `registration` | array | see below | `mode`, `initialAccessToken`, `allowPrivateSchemes` |
| `cimd` | array | see below | `enabled`, `allowedHosts`, `timeout`, `maxBytes`, `cacheMin`, `cacheMax` |
| `clientCredentials` | bool | `true` | Enable the client credentials grant |
| `introspection` | bool | `true` | Enable `/introspect` |
| `personalTokens` | bool | `true` | Personal access tokens on the connections page |
| `connections` | bool or array | `true` | The connections page. In the plugin also an array, see [connections](#connections) |
| `rateLimit` | array | see below | Per endpoint limits, plus the plugin's `cache` key |
| `retentionDays` | int | `7` | Days revoked and expired tokens are kept before `oauth prune` deletes them |

Nested defaults: `lifetimes` `code` 60, `access` 3600, `refresh` 2592000, `family` 31536000, `personalMax`
7776000, `refreshReuseGrace` 30 (all seconds). `registration` `mode` is `open`, `initialAccessToken`
`null`, `allowPrivateSchemes` `false`. `cimd` `enabled` `true`, `allowedHosts` `null` (any host),
`timeout` 5, `maxBytes` 10240, `cacheMin` 300, `cacheMax` 86400. `rateLimit` `authorize` `[30, 60]`,
`token` `[60, 60]`, `register` `[10, 3600]`, `cimd` `[10, 60]`, `introspect` `[600, 60]` (each is
`[requests, seconds]`; `/revoke` counts against `token`, `/introspect` against `rateLimit.introspect`).

Behaviour behind these keys that is worth knowing before production:

- **Private-use schemes are off.** `registration.allowPrivateSchemes` is `false`: dynamic registration and
  metadata documents accept https and loopback http redirect URIs only, as the MCP authorization spec requires.
  Set it to `true` for native clients that redirect to a scheme such as `com.example.app:/oauth/callback`; the
  consent page then calls such a self-registered client "An application on this computer". A public one
  (`token_endpoint_auth_method` `none`) sees the page on every connection; a confidential one (the default of a
  registration that omits the method) with a remembered consent skips it.
  Clients you add with `oauth client add` may always use such schemes. A dynamic registration without
  `application_type` is `native` when none of its redirect URIs is https; one that says `"web"` cannot register
  loopback http.
- **Refresh grace.** `lifetimes.refreshReuseGrace` lets a refresh token that was just rotated be presented
  once more (a client whose response got lost). It does not absorb concurrent refreshes: clients must
  serialize refreshes per token, because two processes refreshing the same token at once trip reuse detection
  and revoke the family. This is a known issue of the core's 1.0.0 betas (see its
  [security](https://github.com/CakeDC/oauth-server/blob/1.x/docs/security.md#known-issue-concurrent-refreshes)
  page).
- **Family cap.** `lifetimes.family` is a hard cap for a whole chain of refresh tokens. It is stored per
  token (`family_started_at`), so it survives pruning.
- **Personal tokens off.** Setting `personalTokens` to `false` stops every existing personal token at once.
  They stay listed and can still be revoked.
- **Scopes at use time.** Effective scopes are computed when a token is used, not only when it is issued.
  Empty effective scopes mean no access. A code exchange intersects the scopes with what the person may hold
  today (`scopes` callback). A refresh narrows only the new access token (by a requested `scope`, the client's
  scopes and the `scopes` callback); the new refresh token keeps the grant, minus scopes the resource no longer
  declares, so a person demoted and promoted again gets the scopes back at the next refresh.
- **`canAuthorize()` runs once.** It is asked at `/authorize`, not again afterwards. After a policy change,
  revoke the affected tokens (see [users](users.md#cutting-a-person-off)).
- **Introspection is a privilege.** A client with `allowIntrospection` can learn about any token of its
  resource. Give it only to resource servers you trust.

## Plugin keys

### `userProvider`

How people are found. See [users](users.md).

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `className` | string or `UserProviderInterface` | `CakeDC\OAuthServer\Identity\OrmUserProvider` | The provider. A class name is built with the settings array; an object is used as is |
| `table` | string | `Users` (with `CakeDC/Users`: `Users.table`, else `CakeDC/Users.Users`) | ORM alias of the users table |
| `finder` | string | `active` | Finder that must find the person. Inactive people are refused by it |
| `displayField` | string or null | table display field (with `CakeDC/Users`: `username`) | Name shown on the consent page |
| `canAuthorize` | callable or null | `null` (everyone) | `fn (IdentityInterface $identity, Client $client, ProtectedResource $resource): bool` |
| `scopes` | callable or null | `null` (no extra limit) | `fn (IdentityInterface $identity, ProtectedResource $resource): ?array` |
| `forClient` | callable or null | `null` (no service identity) | `fn (Client $client, ProtectedResource $resource): mixed` |

### `login`

Where anonymous people sign in.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `url` | string or array | `/login` (with `CakeDC/Users`: its login route) | Login page, as for `Router::url()` |
| `redirectParam` | string | `redirect` | Query parameter the login reads the return URL from |
| `identityAttribute` | string | `identity` | Request attribute holding the identity, when the request has no authentication service |

### `consent`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `layout` | string, false or null | `null` | Layout of the consent and error pages. `null` is the plugin's `CakeDC/OAuthServer.oauth`, `false` renders the template alone, a string is your layout |

### `connections`

`OAuthServer.connections` is `true` or `false` (enable or disable the page, like in the core), or an array:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | The connections page; when `false` it answers 404 |
| `layout` | string, false or null | `null` | Layout of the connections page, with the same meaning as `consent.layout` |

```php
'connections' => ['enabled' => true, 'layout' => 'default'],
```

### `rateLimit`

Besides the core's per endpoint limits, the plugin reads `rateLimit.cache`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `cache` | string or null | `default` | Name of the Cake cache configuration that holds the counters. `null` turns the limits off |

That one cache does more than rate limiting: it also keeps the per client address budget of metadata
document fetches (`rateLimit.cimd`) and the 60 second memory of rejected fetches (a temporary failure, such as a
timeout or a 5xx, is not remembered, unless a stored copy of the client is being served meanwhile). With
`'cache' => null` all three are off. `oauth check` warns about it. Use a cache shared by all your PHP processes
(Redis, Memcached, or file for a single server); an `Array` cache lives in one process and limits nothing in
production.

When the cache fails (Redis is down), rate limiting fails open: requests go through without limits and each one
logs a warning on the `oauth` scope (`Rate limiting is off for this request: the cache failed (...)`), instead of
every endpoint answering 500. Watch for that line.

```php
'rateLimit' => ['cache' => 'oauth', 'token' => [120, 60]],
```

### `users`

Used only with `CakeDC/Users`.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `users.resource` | string | the server's default resource | The resource the integration's token authenticator validates against |
| `users.paths` | list of strings | `tokenPaths`, else the path of the resource | The path prefixes where the integration's token authenticator authenticates. Set `tokenPaths` to the same list so `OAuthServer::csrfSkip()` skips CSRF in the same places |

The authenticator accepts a token only on routes below those paths (the request path and the template of the
matched route), and scope checks inside them are your job. See [cakedc-users](cakedc-users.md) and
[protecting-apis](protecting-apis.md#where-a-token-works).

### `tokenPaths`

A list of path prefixes (`['/api', '/mcp']`) where bearer tokens of this server are expected. Optional.
On routes below these paths `OAuthServer::csrfSkip()` skips CSRF for a request with a bearer token of this
server and for a request with no credential at all (no `Authorization` header, no cookie but the CSRF cookie)
([installation](installation.md#csrf)), and the cakedc/users integration authenticates only there when
`users.paths` is not set. Default: the paths of the declared `resources`, where a resource at the host root
contributes nothing. Set `['/']` to make tokens work on every route; that is a deliberate choice, never a
default: a request without a token or cookies then skips CSRF on every route except the consent and connections
pages and the login action, so every other sign-in form loses its login CSRF protection; avoid it when you have
such forms. Prefixes match on segment boundaries (`/api` covers
`/api/x`, not `/apix`) and are compared with the full request path and with the static part of the matched
route's template, base directory included ([where a token works](protecting-apis.md#where-a-token-works)).
If you set
custom `paths` on your own Token authenticator, set `tokenPaths` to the same list (or pass it to
`csrfSkip($request, $paths)`).

### `csrfCookieName`

The name of the cookie your `CsrfProtectionMiddleware` sets: its `cookieName` option. Default `csrfToken`, the
middleware's default. `OAuthServer::csrfSkip()` ignores that cookie when it decides whether a request without a
token carries a credential: the middleware sets it on every GET, so clients with a cookie jar send it back, and
it proves nothing. Set it when you changed the middleware's option:

```php
'csrfCookieName' => 'XSRF-TOKEN',
```

A value that is not a cookie name (an RFC 7230 token: letters, digits and ``!#$%&'*+-.^_`|~``) is an invalid
setting like any other ([an invalid configuration](#an-invalid-configuration)); `csrfSkip()` then ignores no
cookie. `SessionCsrfProtectionMiddleware` sets no such cookie, so the setting does not apply to it
([installation](installation.md#csrf)). The session cookie's name (`Session.cookie`, else `session_name()`) is
refused too: it would make session requests on the token paths count as having no credential.

### `services`

Advanced. Replacement services, used by the plugin's own tests. Each value must be an instance of the
named interface or `InvalidArgumentException` is thrown.

| Key | Interface |
| --- | --- |
| `clock` | `Psr\Clock\ClockInterface` |
| `transport` | `CakeDC\OAuth\Server\Client\Cimd\HttpTransportInterface` |
| `dns` | `CakeDC\OAuth\Server\Client\Cimd\DnsResolverInterface` |

## How defaults are computed

- **issuer.** `OAuthServer.issuer`, or else `App.fullBaseUrl`. The core canonicalizes it (lowercase
  scheme and host, no default port, no trailing slash) and refuses a query and plain http except on
  localhost. A wrong value fails with a message naming the setting to fix (`OAuthServer.issuer` or
  `App.fullBaseUrl (the default issuer)`).
- **secret.** `OAuthServer.secret`, or else `hash('sha256', Security.salt . '|cakedc-oauth-server')`. A salt
  shorter than 32 characters is refused. Set `OAuthServer.secret` when you want to rotate it without
  changing the salt.
- **table, displayField, login.url.** Taken from `CakeDC/Users` when it is loaded, see
  [cakedc-users](cakedc-users.md).
- **Routing.** The route prefix and the metadata path are computed by the core, without touching the
  secret, so a missing salt does not move the routes. When the configuration is invalid the routes are still
  connected: at `routePrefix` and at the metadata path of the issuer when each of them is valid on its own,
  otherwise at `/oauth` and `/.well-known/oauth-authorization-server`.

## An invalid configuration

An invalid `OAuthServer` setting of any kind (an http issuer behind a TLS proxy, a resource declared with a
string instead of an array, a `Security.salt` shorter than 32 characters without `OAuthServer.secret`, an
unknown key, an invalid `users`, `tokenPaths` or `csrfCookieName` value) keeps the server from being built. It
never takes the application down:

| Where | What happens |
| --- | --- |
| Pages of the application, the login included | Work as usual |
| The metadata document, `token`, `register`, `revoke`, `introspect` | `503` with `{"error": "temporarily_unavailable"}`, `Cache-Control: no-store`, `Retry-After: 300` and the endpoints' usual CORS headers, so browser clients can read it (a CORS preflight gets the usual `204`) |
| The consent and connections pages | `503`, rendered by your application's error page |
| A request with a bearer token of this server (`<tokenPrefix>_at_`, `<tokenPrefix>_pat_`) | `401` from the Token authenticator, never passed on to the session. A POST, PUT, PATCH or DELETE reaches it only when `csrfSkip()` lets it through (next line); otherwise the CSRF middleware answers `403` first |
| `OAuthServer::csrfSkip()` | Still skips the client endpoints. On the routes of a resource it still skips a request with a bearer token of this server, cookies or not (it then gets the `401` above), and a request without any credential, as long as the resources, the issuer and `tokenPaths` can be read; when they cannot, it skips nothing else. A `tokenPrefix` that is not a string leaves no token recognisable as this server's, so a bearer request is then CSRF checked. It never needs the server |
| `bin/cake`, migrations | Work as usual; `bin/cake oauth check` reports the setting to fix |

Each refusal writes the reason to the `oauth` log scope (the setting to fix, never a token or the secret):
look there first when OAuth answers 503 or every token gets 401. A broken configuration costs other requests
next to nothing: the Token authenticator reads only the `tokenPrefix` setting until a request carries such a
token, and `csrfSkip()` reads the route prefix (where the plugin connected its endpoints) on every
state-changing request, plus `tokenPrefix`, the resources and `tokenPaths` for a request with a bearer token of
this server or without any credential (and `csrfCookieName` and the login URL for the latter); neither builds
the server for them. When
`tokenPrefix` itself is not a string, every bearer token is treated as this server's and refused.

## A complete example

```php
// config/app_local.php
use Authentication\IdentityInterface;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Resource\ProtectedResource;

return [
    'OAuthServer' => [
        'issuer' => 'https://example.com',
        'secret' => env('OAUTH_SERVER_SECRET'),
        'tokenPrefix' => 'example',
        'resources' => [
            'https://example.com/mcp' => [
                'name' => 'Example MCP',
                'scopes' => [
                    'content:read' => 'Read your posts',
                    'content:write' => 'Edit drafts',
                    'content:publish' => 'Publish posts',
                ],
                'implies' => [
                    'content:publish' => ['content:write'],
                    'content:write' => ['content:read'],
                ],
                'defaultScopes' => ['content:read'],
            ],
        ],
        'lifetimes' => ['access' => 1800, 'personalMax' => 2592000],
        'refreshTokens' => 'offline_access',
        'registration' => ['mode' => 'open'],
        'cimd' => ['enabled' => true, 'allowedHosts' => null],
        'rateLimit' => ['cache' => 'oauth', 'token' => [120, 60], 'introspect' => [1200, 60]],
        'retentionDays' => 14,
        'userProvider' => [
            'table' => 'Users',
            'finder' => 'active',
            'displayField' => 'email',
            'canAuthorize' => fn (IdentityInterface $user, Client $client, ProtectedResource $resource): bool => (bool)$user['is_editor'],
            'scopes' => fn (IdentityInterface $user, ProtectedResource $resource): ?array => $user['is_admin']
                ? null
                : ['content:read', 'content:write'],
        ],
        'login' => [
            'url' => ['controller' => 'Users', 'action' => 'login', 'plugin' => null],
            'redirectParam' => 'redirect',
        ],
        'consent' => ['layout' => 'oauth'],
        'connections' => ['enabled' => true, 'layout' => 'oauth'],
    ],
];
```

The `oauth` cache used above is an ordinary Cake cache configuration:

```php
// config/app.php (or app_local.php)
'Cache' => [
    'oauth' => [
        'className' => 'Cake\Cache\Engine\RedisEngine',
        'prefix' => 'oauth_',
        'duration' => '+1 hour',
    ],
],
```
