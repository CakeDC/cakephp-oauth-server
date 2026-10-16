# Installation

## Composer

```bash
composer require cakedc/cakephp-oauth-server
```

This also installs the core library `cakedc/oauth-server`. The plugin needs PHP 8.2+, CakePHP 5.0 or later
(CI tests from 5.1.10, the lowest release Composer installs because earlier 5.x releases carry security
advisories), `cakephp/authentication` 3.x and `cakephp/migrations` 4 or 5.

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
  before this plugin.

A broken configuration (an invalid issuer or route prefix) fails at boot on web requests with an error
that names the setting. On the command line the routes fall back to `/oauth` so `bin/cake` keeps working
and `bin/cake oauth check` reports the problem.

## Migrations

```bash
bin/cake migrations migrate -p CakeDC/OAuthServer
```

The migration creates `oauth_clients`, `oauth_authorization_codes`, `oauth_tokens` and `oauth_consents`
with the same shape as the core's `schema/*.sql`: ids are `CHAR(36)`, `oauth_tokens` has
`family_started_at`, and on MySQL and MariaDB the tables use `utf8mb4_bin` so subjects compare case
sensitively. See [deployment](deployment.md#database).

If all of your application's migrations live in `config/Migrations/`, copy the plugin's file
(`config/Migrations/20261016120000_CreateOAuthServerTables.php`) there unchanged and run
`bin/cake migrations migrate` as usual. Do not run both. Later schema changes ship as new migration
files in the plugin; copy them the same way, and run `bin/cake oauth check`, which tells you when a table
is out of date.

## CSRF

OAuth clients call `/oauth/token`, `/oauth/register`, `/oauth/revoke` and `/oauth/introspect` from
outside your site, so they cannot send a CSRF token. Let them through with `OAuthServer::csrfSkip()`,
and keep CSRF protection everywhere else (including the consent and connections forms):

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

`csrfSkip()` returns `true` for two kinds of request:

- a request to the route prefix (`/oauth` by default) plus `token`, `register`, `revoke` or `introspect`;
- a request carrying `Authorization: Bearer <token>` where the token starts with this server's own prefix
  (`<tokenPrefix>_at_` or `<tokenPrefix>_pat_`) **and whose path is below the path of one of your
  resources**. A token is for one resource and works only where that resource lives, so a bearer
  authenticated POST to `/api/posts` (resource `https://example.com/api`) or to your MCP route is not
  rejected with 403, while the same header on `/account/delete` is still CSRF checked. An Authorization
  header is not an ambient credential: a page on another site cannot make the browser send a valid token.

The paths are those of the declared resources (`https://example.com/api` is `/api`, matched on segment
boundaries: `/api` and `/api/x`, not `/apix`), or the list in `OAuthServer.tokenPaths`
([configuration](configuration.md#tokenpaths)) when you set it, or the `$paths` argument of
`csrfSkip($request, $paths)`. A resource at the host root (`https://example.com`) adds no path by
itself: covering every route takes an explicit `'tokenPaths' => ['/']`. Paths are compared after the
normalisation the router applies (each segment URL-decoded on its own, a trailing slash ignored, base
directory included). A path the router and a string comparison could read differently fails closed: one with
an encoded slash (`%2F`), an empty segment (`//`) or `.` / `..` segments is never skipped, and a token
presented there is refused.

Everything else stays CSRF checked: session routes, requests with no bearer or a foreign one, and the
consent and connections pages (`<prefix>/authorize` and `<prefix>/connections` are never skipped, even with
a bearer header, because they are session pages; variants such as a trailing slash or `%61uthorize` are the
same page). Never disable CSRF protection globally.

A global `CsrfProtectionMiddleware` also sets a `csrfToken` cookie on the metadata response, which is
publicly cacheable. Either scope CSRF away from `/.well-known` or accept the cookie.

`bin/cake oauth check` inspects your middleware and fails when the callback does not skip the token
endpoint.

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
API routes. The authenticator accepts a token only below the path of the token's resource (`/api` for
`https://example.com/api`); anywhere else a request that carries one of this server's tokens is refused with
401, so a token for your API can never act as the person on your session pages:

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
- Load `CakeDC/OAuthServer.Token` before the session authenticator. See
  [protecting-apis](protecting-apis.md#authenticator-order).

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
