# Deployment

The core's [deployment](https://github.com/CakeDC/oauth-server/blob/1.x/docs/deployment.md) page covers
https, proxies, CORS, Cloudflare and caches in general. This page is what a CakePHP application needs on
top of it.

## HTTPS and the issuer

The issuer must be https (http is accepted on `localhost` only). It defaults to `App.fullBaseUrl`, so make
that the public https URL, with the right host and no trailing slash. A development value such as
`http://myapp.ddev.site` is refused (`The OAuth issuer is invalid ... Fix App.fullBaseUrl`); set
`OAuthServer.issuer` for a different public name:

```php
'OAuthServer' => ['issuer' => 'https://auth.example.com'],
```

**Set it explicitly in production**, either `OAuthServer.issuer` or `App.fullBaseUrl`. When
`App.fullBaseUrl` is not configured, CakePHP's bootstrap fills it from the `Host` header of the first
request. The issuer is then whatever host name a client sent, and the metadata response, which is publicly
cacheable, can publish an issuer, endpoints and resource URLs that point at a host an attacker chose
(a cache or a client may keep them). With the value configured, the `Host` header no longer matters.

Clients compare the `issuer` in the metadata with the URL they fetched it from and refuse a mismatch, so
spell it exactly as clients use it. Resource URLs in `resources` are https too. Your session cookie must
be `Secure`; behind a proxy that terminates TLS, make Cake aware that the request was https (the next
section).

## Trusted proxies and the client IP

The rate limits count requests per client address, which the plugin reads with
`ServerRequest::clientIp()`. Without `trustProxy` that is `REMOTE_ADDR`. Behind a reverse proxy or a load
balancer every request would then come from the proxy and share one counter. Tell Cake which proxies to
trust, early in the middleware queue, so `clientIp()` reads `X-Forwarded-For`:

```php
// src/Application.php, in middleware(), before the routing middleware
use Cake\Http\ServerRequest;

$middlewareQueue->add(function ($request, $handler) {
    if ($request instanceof ServerRequest) {
        $request->setTrustedProxies(['10.0.0.5', '10.0.0.6']); // your load balancers
    }

    return $handler->handle($request);
});
```

`setTrustedProxies()` turns `trustProxy` on. With `trustProxy` Cake also trusts `X-Real-IP`, `Client-IP` and
the `X-Forwarded-*` headers, so enable it only when the application is reachable through your trusted
proxies alone; otherwise anybody can send `X-Forwarded-For: 1.2.3.4` and dodge the limits. Without
`trustProxy` the forwarding headers are ignored.

Cake does not compare `REMOTE_ADDR` with the proxy list: once `trustProxy` is on, the forwarding headers
of a client that reaches the application directly are believed too, so a forged `X-Forwarded-For` would
dodge the limits. Firewall the application so that only your proxies can reach it.

When the request has no address at all (CLI, integration tests) the plugin counts it as `unknown`.

## The rate limit cache

Limits use the Cake cache named in `OAuthServer.rateLimit.cache` (`default` unless you change it). Use a
cache that all your PHP processes share (Redis, Memcached, or files on a single server). The same cache
holds the metadata document fetch budget; `'cache' => null` turns off all three protections. See
[configuration](configuration.md#ratelimit).

## Claude's egress range

claude.ai calls from Anthropic's egress range `160.79.104.0/21`, a shared range that may serve many people,
so its requests may share rate limits. Give the `token` limit enough room, and do not block or challenge
that range on the OAuth and MCP paths (see the core's note on Cloudflare and WAFs). The range is not exempt:
it stays subject to the plugin's rate limits.

## Applications in a subdirectory

If the application lives below a path (`https://example.com/app`), then:

1. Set the issuer to the full URL, `OAuthServer.issuer = 'https://example.com/app'`. `bin/cake oauth check`
   warns when the issuer path differs from `App.base`.
2. The RFC 8414 metadata document for an issuer with a path is
   `/.well-known/oauth-authorization-server/app`, **at the host root**, not below `/app`. Clients look
   there. The plugin connects that route inside the application, so the web server must send the request
   to the application:

The location for `/app` must already hand requests to the application's front controller (with the
`try_files` rule of your normal subdirectory setup). The snippet below was not tested on a real
subdirectory install; adapt it to your layout.

```nginx
# Host root: hand the well-known URL to the application below /app.
location = /.well-known/oauth-authorization-server/app {
    rewrite ^ /app/.well-known/oauth-authorization-server/app last;
}
```

The endpoints keep the prefix inside the application: `https://example.com/app/oauth/token`.

For a root install nothing is needed: the issuer is `App.fullBaseUrl` and the route is
`/.well-known/oauth-authorization-server`.

## nginx

Do not block `/.well-known/` (a "deny dotfiles" rule does by accident) and send everything else to Cake's
front controller:

```nginx
server {
    listen 443 ssl;
    server_name example.com;
    root /var/www/app/webroot;

    location ^~ /.well-known/ {
        try_files $uri /index.php?$args;
    }

    location ~ /\.(?!well-known) {
        deny all;
    }

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php-fpm.sock;
    }
}
```

nginx passes the `Authorization` header to PHP-FPM. Do not add CORS `add_header` lines for `/oauth/` or
`/.well-known/`: the handlers already send them, and a duplicated `Access-Control-Allow-Origin` makes
browsers reject the response.

## Database

- **Migrations.** Schema changes ship as new migration files. Copy new files into your application's
  `config/Migrations/` (or run `migrations migrate -p CakeDC/OAuthServer`) on every upgrade;
  `bin/cake oauth check` reports a missing table or column.
- **Collation.** On MySQL and MariaDB the tables use `utf8mb4_bin`, so subjects and ids compare case and
  accent sensitively (user `Alice` is not `alice`). `utf8mb4_bin` is a PAD SPACE collation, so two subjects
  that differ only by trailing spaces compare equal: do not create such ids. `oauth check` fails when a
  column has another collation.
- **Ids.** Ids are `CHAR(36)`, never native UUID columns, on every database.
- **Transactions.** Never run the OAuth endpoints inside a request-wide database transaction (a middleware
  that wraps every request in `BEGIN ... COMMIT`). A rollback after an error could undo tokens already
  handed out, and checks after an atomic update could read a stale snapshot. Exclude the OAuth routes from
  such a wrapper.

## Cron

Schedule `bin/cake oauth prune` daily. See [commands](commands.md#oauth-prune).

## Caches

Pages and token responses are sent with `Cache-Control: no-store`. Only the metadata document may be
cached (300 seconds). Do not put a cache in front of `/oauth/` or your MCP endpoint that ignores
`Cache-Control`. Note that a global CSRF middleware sets a `csrfToken` cookie even on the metadata
response; keep it from `/.well-known` with your own skip rule or accept it, but make sure no cache stores
that cookie for other visitors.
