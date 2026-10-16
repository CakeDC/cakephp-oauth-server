# Troubleshooting

Start with `bin/cake oauth check`: most problems show up there. Core-level problems (issuer mismatch,
`invalid_target`, redirect URI errors, CIMD fetch failures, clock skew) are covered in the core's
[troubleshooting](https://github.com/CakeDC/oauth-server/blob/1.x/docs/troubleshooting.md). This page lists
what is specific to CakePHP.

## 403 on /oauth/token (or register, revoke, introspect)

Cake's `CsrfProtectionMiddleware` refused a call from an OAuth client, which cannot send a CSRF token.
Skip those paths:

```php
$csrf->skipCheckCallback(fn (ServerRequestInterface $request): bool => OAuthServer::csrfSkip($request));
```

`oauth check` reports `add OAuthServer::csrfSkip($request) to the CsrfProtectionMiddleware
skipCheckCallback`. If you changed `routePrefix`, `csrfSkip()` follows it. See
[installation](installation.md#csrf).

## 403 on a bearer POST to your API or MCP endpoint

The CSRF check refused a request that carries one of this server's tokens. `csrfSkip()` skips it only when
all of this holds ([installation](installation.md#csrf)):

- the token validates for one of your resources: an expired, revoked or made up token gets 403 here, before
  the authenticator could answer 401;
- the request is on the routes of that resource: the request path and the static part of the matched
  route's template are below the resource's path (or `OAuthServer.tokenPaths`). A route that starts with a
  placeholder (`/{lang}/api/...`) is not; give it a static prefix (`/api/{lang}/...`);
- `CsrfProtectionMiddleware` comes after `RoutingMiddleware`.

## 403 when pressing Allow or Revoke

A form on the consent or connections page was posted without a CSRF token. This happens with a template
override that writes `<form>` by hand. Build the form with `$this->Form->create(null, ['url' => ...])`
([pages](pages.md#forms-and-csrf)).

## Login loops

- The login does not send people back to the address in the `redirect` query parameter. Fix the login
  action, or set `OAuthServer.login.redirectParam` to the parameter it reads
  ([users](users.md#the-login-url-and-the-redirect-parameter)).
- `OAuthServer.login.url` points at a page that itself requires a login. Point it at the real login.
- The application signs people in with HTTP Basic or a token only. The consent page needs a session login
  and refuses stateless identities, so it sends people to the login page again and again. Add a session
  login.
- The account is inactive for the configured `finder`. The person is treated as signed out.

## 404 on /.well-known/oauth-authorization-server

- Subdirectory install: the metadata document must be served at the host root and the web server has to
  hand it to the application ([deployment](deployment.md#applications-in-a-subdirectory)).
- A "deny dotfiles" rule in the web server blocks `/.well-known/`
  ([deployment](deployment.md#nginx)).
- The issuer has a path, so the URL ends with that path
  (`/.well-known/oauth-authorization-server/app`).

## "The OAuth issuer is invalid"

The issuer (`OAuthServer.issuer`, or `App.fullBaseUrl` when it is not set) must be an absolute https URL
without a query; http works on localhost only. The message names the setting to fix. It shows in
`bin/cake oauth check` and in the `oauth` log; the OAuth endpoints answer 503 until it is fixed, while the rest of
the application keeps working.

## 503 on every OAuth endpoint, or 401 for every token

The `OAuthServer` configuration is invalid (an unknown key, a wrong type, a resource declared with a string, a
short `Security.salt` without `OAuthServer.secret`, an invalid `users` or `tokenPaths` value), so the server
cannot be built. The plugin fails closed on its own routes only: the endpoints answer 503 (with
`Retry-After: 300`), the consent and
connections pages show your error page with 503, and every token of this server gets 401 with
`The access token cannot be validated.`; your other pages keep working. The `oauth` log has one line per refusal
with the reason. Run `bin/cake oauth check` and fix what it names
([configuration](configuration.md#an-invalid-configuration)).

The same 401 appears for a single Token authenticator whose `resource` is not declared, whose resource is at the
host root without `paths`, or whose `paths` is not a list of path prefixes; the `Authenticators` line of
`oauth check` names it.

## 401 "The access token is not valid at this address"

A valid token was sent to a route outside its resource's path. A token works only on the routes of its
resource: the request path and the static part of the template of the route that matched it must both be
below the path of the resource (`/api` for `https://example.com/api`, or the authenticator's `paths`);
anywhere else the request is refused. Check that:

- you call the resource at its own URL;
- the route has a static prefix within the paths: a route `/{lang}/orders` is not below `/api`, even when it
  matches the URL `/api/orders`, while `/api/{lang}/orders` is;
- `AuthenticationMiddleware` comes after `RoutingMiddleware` (before routing every token is refused).

Set `paths` (and `OAuthServer.tokenPaths`) if your routes live elsewhere
([protecting-apis](protecting-apis.md#where-a-token-works)).

## "The `Token` alias has already been loaded"

With `cakedc/users`, load the authenticator as `CakeDC/OAuthServer.OAuthServerToken` (the integration
does it for you). An authentication collection aliases authenticators by class name without the plugin, so
`CakeDC/OAuthServer.Token` clashes with the `Token` authenticator of cakedc/users.

## The consent page has no styles from my application

The default layout is the plugin's own. If you set `consent.layout` or `connections.layout`, the pages keep
the core's strict Content-Security-Policy plus same-origin styles, images and fonts, and scripts do not
run. A layout that needs JavaScript or loads CSS from another host will look unstyled. Use a layout that
works with same-origin CSS only ([pages](pages.md#using-your-own-layout)).

A layout that needs variables set by your own controllers (a menu, the current user) will fail or look
empty, because the plugin's controller does not set them.

## RBAC redirects with cakedc/users

The OAuth endpoints are redirected to the login or denied by RBAC. The plugin adds one `bypassAuth` rule
through `RbacPermissionsProvider`; it is missing when you set your own
`Auth.RbacPolicy.adapter.permissions_provider_class` or replaced the rules wholesale. `oauth check` prints
the `RBAC` line. Add `OAuthServer::rbacPermissions()` to `config/permissions.php`
([cakedc-users](cakedc-users.md#when-you-override-the-authenticators-or-the-permissions-wholesale)).

## invalid_target

The `resource` a client sends does not match a declared resource. The identifier is compared as a string:
`https://example.com/mcp` and `https://example.com/mcp/` differ. Use the same string in
`OAuthServer.resources`, in your protected resource metadata and in the URL the client has. See the core's
[troubleshooting](https://github.com/CakeDC/oauth-server/blob/1.x/docs/troubleshooting.md).

## Rate limit 429 for everybody

Behind a proxy every request comes from the proxy address. Configure trusted proxies
([deployment](deployment.md#trusted-proxies-and-the-client-ip)). Claude's shared egress range
`160.79.104.0/21` may also share limits (it is not exempt from them); raise `rateLimit.token`.

## No rate limiting, or no CIMD protection

`rateLimit.cache` is `null` (or the named cache does not exist). `oauth check` warns or fails.

## What each oauth check line means

See the table in [commands](commands.md#oauth-check). The ones that most often fail:

| Line | Usual cause |
| --- | --- |
| `Secret` | `OAuthServer.secret` shorter than 32 characters, or no usable `Security.salt` |
| `Configuration` | An invalid `OAuthServer` setting; the message names it |
| `Tables` | The migration was not run (`bin/cake migrations migrate -p CakeDC/OAuthServer`), or an old copy of it was (a missing column or unique key); copy the current file. The line names the connection of the plugin's tables, which is where it looks |
| `Users` | The users table has no `active` finder; add `findActive()` or set `userProvider.finder` |
| `Routes` | A route of your application connected before the plugin's takes `<prefix>/token` |
| `Middleware` | `CsrfProtectionMiddleware` or `AuthenticationMiddleware` runs before `RoutingMiddleware`, where bearer requests cannot be told apart |
| `CSRF` | The skip callback is missing, it skips session pages too (a callback like `fn () => true`), or there is no CSRF middleware at all |
| `Authenticators` | The Session authenticator is loaded before the Token one, there is no Token authenticator, or it refuses every token (an undeclared `resource`, a root resource without `paths`) |
| `RBAC` | The bypass rule is missing |
| `Rate limiting` | The cache configuration named in `rateLimit.cache` does not exist, or it is an `Array` or `Null` engine, which keeps nothing between requests |
| `Client metadata documents` | `ext-curl` is not installed |

## Scope names with dots on the connections form

The form posts `scope:<name>` fields and reads them from the raw request body (`php://input`), because PHP
turns dots in field names into underscores. PHP-FPM provides the raw body for urlencoded POSTs. If you
write your own handler, read the body the same way.
