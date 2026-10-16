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
without a query; http works on localhost only. The message names the setting to fix. On the CLI this does
not stop `bin/cake`; web requests fail at boot.

## Every request fails after a configuration change

The Token authenticator builds the OAuth server in its constructor, so an invalid `OAuthServer`
configuration (an undeclared resource in the authenticator's `resource`, an unknown key, a wrong type)
breaks every request, including the login page. Run `bin/cake oauth check` and fix what it names.

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
`160.79.104.0/21` may also share limits; raise `rateLimit.token`.

## No rate limiting, or no CIMD protection

`rateLimit.cache` is `null` (or the named cache does not exist). `oauth check` warns or fails.

## What each oauth check line means

See the table in [commands](commands.md#oauth-check). The ones that most often fail:

| Line | Usual cause |
| --- | --- |
| `Secret` | `OAuthServer.secret` shorter than 32 characters, or no usable `Security.salt` |
| `Tables` | The migration was not run (`bin/cake migrations migrate -p CakeDC/OAuthServer`), or an old copy of it was; copy the current file |
| `Users` | The users table has no `active` finder; add `findActive()` or set `userProvider.finder` |
| `CSRF` | The skip callback is missing |
| `RBAC` | The bypass rule is missing |
| `Rate limiting` | The cache configuration named in `rateLimit.cache` does not exist |
| `Client metadata documents` | `ext-curl` is not installed |

## Scope names with dots on the connections form

The form posts `scope:<name>` fields and reads them from the raw request body (`php://input`), because PHP
turns dots in field names into underscores. PHP-FPM provides the raw body for urlencoded POSTs. If you
write your own handler, read the body the same way.
