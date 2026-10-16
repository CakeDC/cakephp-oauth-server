# Installation

## Composer

```bash
composer require cakedc/cakephp-oauth-server:^1.0@beta cakedc/oauth-server:^1.0@beta
```

This installs the plugin and the core library `cakedc/oauth-server`. Both are betas, and Composer reads
stability flags such as `@beta` only from your application's `composer.json`, never from the plugin's: an
application with the default `"minimum-stability": "stable"` cannot install the beta core through the plugin, so
the command names both packages. Alternatively, set this in your `composer.json` and require the plugin alone:

```json
"minimum-stability": "beta",
"prefer-stable": true
```

The plugin needs PHP 8.2+, CakePHP 5.1.10 or later, `cakephp/authentication` 3.3.6 or later and
`cakephp/migrations` 4 or 5.

Those floors are the oldest releases without published security advisories. Earlier CakePHP 5 releases and
`cakephp/authentication` before 3.3.6 have advisories, and Composer refuses to install them by default; one of
them is an open redirect through the `redirect` parameter of the login (PKSA-bz6x-t8z8-r26p), which is exactly
how the consent page sends an anonymous person to sign in and back. So the plugin does not declare support for
them.

## Load the plugin

```php
// src/Application.php
public function bootstrap(): void
{
    parent::bootstrap();
    $this->addPlugin('CakeDC/OAuthServer');
}
```

Loading the plugin does these things:

- connects the routes (see [Routes](#routes));
- registers the `oauth` commands;
- registers a log file for the `oauth` log scope when no engine handles it (see
  [security](security.md#logging));
- registers the loader of the `oauth_server` translation domain, so the plugin's messages and your own
  `resources/locales/<locale>/oauth_server.po` overrides work (see [pages](pages.md));
- puts the core `AuthorizationServer` in the application's container, so controllers and commands can type-hint
  it (it is the same object as `OAuthServer::server()`);
- if `CakeDC/Users` is loaded, applies the [cakedc/users integration](cakedc-users.md). Load `CakeDC/Users`
  before this plugin (see [why](cakedc-users.md#plugin-order)).

A broken `OAuthServer` configuration (an invalid issuer, a resource declared with a string, a short
`Security.salt`, an unknown key) never takes the application down. Its pages, the login included, and
`bin/cake` keep working, while everything OAuth fails closed: the plugin's routes answer 503 and log the
reason, and a token of this server gets 401. `bin/cake oauth check` names the setting to fix. See
[configuration](configuration.md#an-invalid-configuration).

## Migrations

```bash
bin/cake migrations migrate -p CakeDC/OAuthServer
```

The migration creates `oauth_clients`, `oauth_authorization_codes`, `oauth_tokens` and `oauth_consents`
with the same shape as the core's `schema/*.sql`: ids are `CHAR(36)`, `oauth_tokens` has
`family_started_at`, and on MySQL and MariaDB the tables use `utf8mb4_bin` so subjects compare case
sensitively. See [deployment](deployment.md#database).

If all of your application's migrations live in `config/Migrations/`, copy the plugin's files
(`config/Migrations/20261016120000_CreateOAuthServerTables.php` and
`config/Migrations/20261017120000_AddOAuthCodesSubjectIndex.php`) there unchanged and run
`bin/cake migrations migrate` as usual. Do not run both. Later schema changes ship as new migration
files in the plugin; copy them the same way, and run `bin/cake oauth check`, which tells you when a table
is out of date.

The second file adds an index on `oauth_authorization_codes (subject)`, which revoking a person or one of their
connections uses to delete the codes they have not exchanged yet. It only adds the index, and does nothing when
the index exists already.

## CSRF

OAuth clients call `/oauth/token`, `/oauth/register`, `/oauth/revoke` and `/oauth/introspect` from
outside your site, and API and MCP clients call your resources' routes, so they cannot send a CSRF token. Let
them through with `OAuthServer::csrfSkip()`, and keep CSRF protection everywhere else (including the consent
and connections forms):

```php
// src/Application.php
use Cake\Http\Middleware\CsrfProtectionMiddleware;
use Cake\Http\MiddlewareQueue;
use CakeDC\OAuthServer\OAuthServer;
use Psr\Http\Message\ServerRequestInterface;

public function middleware(MiddlewareQueue $middlewareQueue): MiddlewareQueue
{
    $csrf = new CsrfProtectionMiddleware(['httponly' => true]);
    $csrf->skipCheckCallback(fn (ServerRequestInterface $request): bool => OAuthServer::csrfSkip($request));

    return $middlewareQueue
        ->add(new ErrorHandlerMiddleware(Configure::read('Error'), $this))
        ->add(new AssetMiddleware(['cacheTime' => Configure::read('Asset.cacheTime')]))
        ->add(new RoutingMiddleware($this))
        ->add(new BodyParserMiddleware())
        ->add($csrf)
        ->add(new AuthenticationMiddleware($this));
}
```

`csrfSkip()` returns `true` for three kinds of request:

- a request to the route prefix (`/oauth` by default) plus `token`, `register`, `revoke` or `introspect`;
- a request **on the routes of one of your resources** that carries `Authorization: Bearer <token>` where the
  token starts with this server's own prefix (`<tokenPrefix>_at_` or `<tokenPrefix>_pat_`), whatever else it
  carries, cookies included. Only the prefix is read and the token is never looked up, so this costs no query.
  The Token authenticator answers the request: a valid token runs as its owner, and an expired, revoked or made
  up token of this server, one issued for another resource, or one whose owner was deactivated, gets 401 with
  `WWW-Authenticate: Bearer ... error="invalid_token"`, the signal a client needs to refresh its token or to
  sign in again;
- a request **on the routes of one of your resources** that carries no credential at all: no `Authorization`
  header, no cookie other than the CSRF middleware's own (`csrfToken`, see below), no HTTP Basic or Digest
  credentials and no user the web server authenticated (`REMOTE_USER`). CSRF protects those ambient
  credentials, and such a request has none, so the check would protect nothing. Your route answers it: its own
  401 can start a client's discovery (MCP clients POST every message, the first one without a token).

Why a bearer token is enough: CSRF works by making a browser send what it sends by itself (cookies, HTTP Basic
credentials) with a request that another site chose. A page on another site cannot make the browser add an
`Authorization` header; that takes a CORS preflight your application approves with credentials for that site,
and an application that does so has already given that site everything CSRF protects. With the Token
authenticator loaded before the session, cookie (remember-me) and form authenticators, the session is never
consulted for a request with a bearer token of this server: a token that does not validate gets the 401 above,
never the signed in person's session. `bin/cake oauth check` fails when a stateful authenticator comes first
([authenticator order](protecting-apis.md#authenticator-order)).

The CSRF cookie does not count. `CsrfProtectionMiddleware` sets it on every GET that comes without one, so a
client with a cookie jar (httpx in the MCP Python SDK, most REST clients) sends it back with its next POST, and
it proves nothing about who sent that POST. Every other cookie counts, a load balancer's sticky cookie
(`AWSALB`) included, so a request without a token that carries one is CSRF checked; with a bearer token of this
server cookies never matter. If you changed the middleware's `cookieName` option, set
`OAuthServer.csrfCookieName` to the same name ([configuration](configuration.md#csrfcookiename)):

```php
// config/app_local.php
'OAuthServer' => [
    // The cookieName option of your CsrfProtectionMiddleware (csrfToken by default).
    'csrfCookieName' => 'XSRF-TOKEN',
],
```

With `SessionCsrfProtectionMiddleware` the CSRF token lives in the session, so there is no CSRF cookie to
ignore and the session cookie counts like any other: a request without a token from a client that kept the
session cookie of an earlier GET is CSRF checked, while requests with a bearer token of this server are skipped
as above.

"On the routes of one of your resources" is the rule of the Token authenticator
([protecting-apis](protecting-apis.md#where-a-token-works)): both the request path and the static part of the
template of the route that matched it must be within the resource's paths. Those are the path of the resource
(`https://example.com/api` is `/api`, matched on segment boundaries: `/api` and `/api/x`, not `/apix`), or the
list in `OAuthServer.tokenPaths` ([configuration](configuration.md#tokenpaths)) for every resource when you set
it, or the `$paths` argument of `csrfSkip($request, $paths)`. A resource at the host root
(`https://example.com`) adds no path by itself: covering every route takes an explicit
`'tokenPaths' => ['/']`. A route whose template starts with a placeholder (`/{tenant}/account/delete`) is not
on the routes of `/api`, even for the URL `/api/account/delete`. Paths are compared after the normalisation the
router applies (each segment URL-decoded on its own, a trailing slash ignored, base directory included). A path
the router and a string comparison could read differently fails closed: one with an encoded slash (`%2F`), an
empty segment (`//`) or `.` / `..` segments is never skipped, and a token presented there is refused.

Add `CsrfProtectionMiddleware` after `RoutingMiddleware`, as above and in the CakePHP application skeleton.
Before routing there is no matched route, so no request is skipped there for being on a resource's routes (the
client endpoints still are). `csrfSkip()` never throws and never builds the server. The client endpoints are
skipped with any configuration, a broken one included (they answer 503 then), because they are found where the
plugin connected their routes. When the resources, the issuer or `tokenPaths` cannot be read, nothing else is
skipped and a warning goes to the `oauth` log; so is a request without a token whose login page cannot be told
(an `OAuthServer.login.url` that names a route that does not exist).

Everything else stays CSRF checked: session routes (with or without cookies), requests on a resource's routes
that carry a cookie other than the CSRF cookie but no bearer token of this server, requests with another
`Authorization` scheme or another server's token, the login page, and the consent and connections pages
(`<prefix>/authorize` and `<prefix>/connections` are never skipped, whatever the request carries, because they
are session pages; variants such as a trailing slash or `%61uthorize` are the same page). Never disable CSRF
protection globally.

The login page (`OAuthServer.login.url`) is never skipped, even when the token paths cover it. A string URL is
the page at its path. A URL array (the default with cakedc/users) also covers every other route to the same
action, such as `/Users/login` through the fallback routes: plugin, prefix, controller and action are compared,
and the positional values when the array gives some. Give the login as an array when other routes reach its
action.

Keep session pages out of your resources' paths. With `'tokenPaths' => ['/']` every route is on the routes of
a resource, so every sign-in form is one: a request without a token or cookies skips the check everywhere except
the consent and connections pages and the login, and a form that signs someone in without a session (a second
login action, a registration that signs the new account in) loses its login CSRF protection there. Avoid
`['/']` when you have such forms. Give your `Form` authenticator a `loginUrl`, as in the example under
[authentication](#authentication): without one it reads credentials from every POST, wherever it lands. And when
browsers authenticate to your application on a resource's routes by something `csrfSkip()` cannot see, such as
a TLS client certificate, do not use `csrfSkip()` for those routes.

A global `CsrfProtectionMiddleware` also sets a `csrfToken` cookie on the metadata response, which is
publicly cacheable. Either scope CSRF away from `/.well-known` or accept the cookie.

`bin/cake oauth check` inspects your middleware (`CsrfProtectionMiddleware` or
`SessionCsrfProtectionMiddleware`): it fails when the callback does not skip the token endpoint or when it also
skips the consent page, the connections page, the home page or the login. When the CSRF or the authentication
middleware runs before `RoutingMiddleware` it fails if a Token authenticator of this plugin is loaded (its tokens
cannot work there) and warns otherwise. It also fails when a session, cookie or form authenticator comes before
the Token authenticator.

## Routes

The plugin connects these routes in its own `routes()`, so you add nothing to `config/routes.php`:

| Route | Action |
| --- | --- |
| `/.well-known/oauth-authorization-server` (plus the issuer's path, if any) | `metadata` |
| `<prefix>/authorize` | `authorize` |
| `<prefix>/token` | `token` |
| `<prefix>/register` | `register` |
| `<prefix>/revoke` | `revoke` |
| `<prefix>/introspect` | `introspect` |
| `<prefix>/connections` | `connections` |

`<prefix>` is `OAuthServer.routePrefix` (default `/oauth`). All of them go to
`CakeDC\OAuthServer\Controller\OAuthController`. The paths come from the core's `ServerConfig`, so the
metadata document always names URLs that exist. For an application in a subdirectory read
[deployment](deployment.md#applications-in-a-subdirectory).

## Authentication

The consent and connections pages need a person who is signed in with a browser session. The plugin
reads the identity from the request attribute of your `cakephp/authentication` setup (`identity` by
default, or the attribute your authentication service reports).

A minimal `getAuthenticationService()`, with a form login and the plugin's token authenticator for your
API routes. The authenticator accepts a token only on the routes of the token's resource: the request path and
the template of the route that matched it must both be below the resource's path (`/api` for
`https://example.com/api`). Anywhere else a request that carries one of this server's tokens is refused with
401, so a token for your API cannot act as the person on a session route that is not connected below `/api`
([where a token works](protecting-apis.md#where-a-token-works)). Load `AuthenticationMiddleware` after
`RoutingMiddleware`:

```php
// src/Application.php
use Authentication\AuthenticationService;
use Authentication\AuthenticationServiceInterface;
use Authentication\AuthenticationServiceProviderInterface;
use Authentication\Middleware\AuthenticationMiddleware;
use Cake\Routing\Router;
use Psr\Http\Message\ServerRequestInterface;

class Application extends BaseApplication implements AuthenticationServiceProviderInterface
{
    public function getAuthenticationService(ServerRequestInterface $request): AuthenticationServiceInterface
    {
        $service = new AuthenticationService([
            'unauthenticatedRedirect' => Router::url(['controller' => 'Users', 'action' => 'login']),
            'queryParam' => 'redirect',
        ]);

        // The token first: a session cookie must not hide a revoked or foreign bearer token.
        $service->loadAuthenticator('CakeDC/OAuthServer.Token', ['resource' => 'https://example.com/api']);
        $service->loadAuthenticator('Authentication.Session');
        $service->loadAuthenticator('Authentication.Form', [
            'fields' => ['username' => 'email', 'password' => 'password'],
            'loginUrl' => Router::url(['controller' => 'Users', 'action' => 'login']),
        ]);
        $service->loadIdentifier('Authentication.Password', [
            'fields' => ['username' => 'email', 'password' => 'password'],
        ]);

        return $service;
    }
}
```

Rules to know:

- When an anonymous person reaches `/oauth/authorize`, the plugin redirects to `OAuthServer.login.url`
  (default `/login`) with the return address in the `redirect` query parameter. Both are
  [configurable](configuration.md#login). Your login action must send people back to that address after
  signing in.
- A bearer token is never a browser login. The consent and connections pages accept a session login only.
  Stateless authenticators (Token, HttpBasic, JWT, ...) and impersonation are refused, so those requests
  get the login page (a request that carries one of this server's tokens there is refused with 401, being
  outside the token's path). An application that signs people in only with HTTP Basic needs a session login for
  the consent page, otherwise people may loop between the login and the consent page.
- Load `CakeDC/OAuthServer.Token` before the session, cookie (remember-me) and form authenticators;
  `bin/cake oauth check` fails otherwise. See [protecting-apis](protecting-apis.md#authenticator-order).
- Give the `Form` authenticator a `loginUrl`, as above. Without one it reads credentials from every POST to
  any route, and on the routes of a resource a POST without a token or cookies is not CSRF checked
  ([CSRF](#csrf)).

## Authorization

If the application uses `cakephp/authorization` with `requireAuthorizationCheck`, nothing changes for the
plugin: `OAuthController` marks its own requests as authorized (it calls `skipAuthorization()` when the
request has an `authorization` attribute) and never for any other controller.

## Check the installation

```bash
bin/cake oauth check
```

Run it after every configuration change and on every deployment. It is described in
[commands](commands.md#oauth-check).
