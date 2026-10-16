# Protecting APIs

To accept the tokens this server issues on your own routes (a JSON API, an MCP endpoint), load the
plugin's authenticator into your `cakephp/authentication` service. It reads `Authorization: Bearer ...`,
validates the token with the core's `TokenValidator` and, when it is good, produces an identity that
behaves like the person's own identity and also carries the token.

The core page [protecting resources](https://github.com/CakeDC/oauth-server/blob/1.x/docs/protecting-resources.md)
explains the token model (scopes are computed when the token is used, personal tokens, revocation).

## Loading the authenticator

```php
// src/Application.php
public function getAuthenticationService(ServerRequestInterface $request): AuthenticationServiceInterface
{
    $service = new AuthenticationService([
        'unauthenticatedRedirect' => Router::url(['controller' => 'Users', 'action' => 'login']),
        'queryParam' => 'redirect',
    ]);

    $service->loadAuthenticator('CakeDC/OAuthServer.Token', [
        'resource' => 'https://example.com/api',
        'resourceMetadataUrl' => 'https://example.com/.well-known/oauth-protected-resource',
    ]);
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
```

Options of `CakeDC\OAuthServer\Authenticator\TokenAuthenticator`:

| Option | Default | Meaning |
| --- | --- | --- |
| `resource` | `null` | The resource identifier the token must be issued for. `null` is the server's default resource. It must be declared in `OAuthServer.resources` (in any spelling); otherwise every token of this server is refused with 401 |
| `paths` | the path of the resource identifier | Path prefixes where the authenticator authenticates, for example `['/api']`. Matched on segment boundaries (`/api` covers `/api` and `/api/x`, not `/apix`), base directory included, after the router's normalisation (a path with `%2F`, `//` or `.` / `..` segments matches nothing). Both the request path and the static part of the template of the route that matched it must be within them ([where a token works](#where-a-token-works)). A resource at the host root (`https://example.com`) needs `paths` set explicitly (`['/']` covers every route); otherwise, and for an invalid list, every token of this server is refused with 401 |
| `header` | `Authorization` | The request header that carries the bearer token |
| `resourceMetadataUrl` | `null` | URL of the protected resource metadata document (RFC 9728) that your endpoint serves. When set, it is added to the 401 challenge as `resource_metadata` |
| `skipTwoFactorVerify` | `true` | For `cakedc/users`: a token is not asked for a second factor |

With `CakeDC/Users` loaded, the plugin registers the authenticator itself under the name
`OAuthServerToken`; see [cakedc-users](cakedc-users.md).

Building the authenticator reads no configuration, so a wrong option or a broken `OAuthServer` configuration
cannot break the pages of your application, the login included. The resource, the paths and the server are
resolved on the first request that carries a bearer token with this server's prefix. When that fails (an
undeclared `resource`, a root resource without `paths`, an invalid `paths` list, a configuration the server
cannot be built from) the request gets the 401 challenge with `The access token cannot be validated.`, it is
never handed to the next authenticator, and the reason goes to the `oauth` log. `bin/cake oauth check` reports
the same problem on its `Authenticators` line; run it after every change.

## Authenticator order

Load `CakeDC/OAuthServer.Token` before the session authenticator. The first authenticator that succeeds
wins: if the session came first, a request that carries a session cookie and a revoked or foreign bearer
token would run as the session user and the token would never be checked. With the token first, a request
with a bearer token on `/oauth/authorize` is the token's request (not a browser login), and being outside
the token's path it is refused with 401.

## Where a token works

A token is for one resource, and that resource lives at its URL (RFC 8707). The authenticator therefore
authenticates only on the routes of that resource, which it tells by two checks against its `paths` (by
default the path of the `resource`):

- the request path, base directory included, is within the paths;
- the route that matched the request is within them too: the static part of its template (everything
  before the first `{placeholder}` or `*`, with the base directory in front) must be within the paths.
  The router, not the URL, decides which action runs, so this is the check that matters for your session
  pages.

A request that carries one of this server's tokens and fails either check is challenged with 401
(`error="invalid_token"`, "The access token is not valid at this address") and never authenticated, even
when it also carries a session cookie. Requests without one of this server's tokens, or with a foreign one,
pass on to your other authenticators as before.

So a token for `https://example.com/api` can act as the person on a route whose template starts with
`/api`, and on no other route. Some consequences:

- A route whose template starts with a placeholder (`/{tenant}/account/delete`, `/{lang}/...`, a `/{slug}`
  catch-all, the fallbacks `/{controller}/{action}/*`) is never on the routes of `/api`, even for the URL
  `/api/account/delete`. Give the routes of a resource a static prefix within its paths (`/api/{tenant}/...`,
  not `/{tenant}/api/...`), or the token is refused on them. A static part that ends inside a segment
  (`/api-{version}`) counts only up to the last complete segment.
- Everything you connect below the resource's path is part of the resource: a session page at
  `/api/account/delete` accepts the token. Keep session pages out of your resources' paths.
- `paths` set to `['/']` accepts the token on every route of the application, session pages included.
  Only the consent and connections pages still refuse it as a login.
- Load `RoutingMiddleware` before `AuthenticationMiddleware`, as the CakePHP application skeleton does.
  Before routing there is no matched route, and every one of this server's tokens is refused with 401.

Inside its routes the token proves who the caller is and which scopes were granted, nothing more: your
actions still check `OAuthServer::token($request)->hasScope(...)`. CSRF is skipped for a bearer request by
the same two checks, and only for a token that validates (see [installation](installation.md#csrf)); keep
both lists consistent when you set custom `paths` by passing the same list to
`OAuthServer::csrfSkip($request, $paths)` or by setting `OAuthServer.tokenPaths`.

Use one Token authenticator per authentication service. A token carrying this server's prefix but issued
for a different resource than the authenticator's `resource` is challenged with 401.

## Why it only challenges its own tokens

`cakephp/authentication` asks every stateless authenticator for its challenge when authentication fails,
before it tries the next one. So that it cannot block other schemes, this authenticator answers 401 only
for a request that carries a bearer token with this server's prefix (`<tokenPrefix>_at_...` or
`<tokenPrefix>_pat_...`). A request with no `Authorization` header, with another scheme (Basic, a JWT) or with
a token of another system passes on to the next authenticator.

That means anonymous requests are not challenged by this authenticator. If you want a 401 for requests with
no credentials on your API routes, use `cakephp/authentication`'s own handling for that: the
`AuthenticationComponent` throws `UnauthenticatedException` for a missing identity while its
`requireIdentity` option is `true` (the default), or you check `getIdentity()` yourself.

## The 401 response

For an invalid, expired, revoked or foreign own-prefix token the authenticator throws
`AuthenticationRequiredException`, which Cake turns into this response:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource", error="invalid_token", error_description="The access token is invalid."
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache

{"error":"invalid_token","error_description":"The access token is invalid."}
```

`resource_metadata` appears only when `resourceMetadataUrl` is set. The description comes from the core's
`ValidationFailure`.

## CSRF on token routes

A bearer authenticated POST, PUT or DELETE to your API route would be rejected by Cake's CSRF middleware,
because API clients send no CSRF token. `OAuthServer::csrfSkip()` (see [installation](installation.md#csrf))
returns `true` for requests carrying a valid bearer token of this server on the routes of its resource, so
using it in `skipCheckCallback()` is enough. Keep CSRF protection on for your session routes and never
disable it globally: requests with no bearer token, with a foreign one, or with one of this server's prefix
that does not validate (expired, revoked, made up) are still checked, and get 403 before the authenticator
sees them.

## Reading the token and checking scopes

`OAuthServer::token($request)` returns the `ValidatedToken` of a request authenticated by the Token
authenticator, or `null`. It also works when `cakephp/authorization` has wrapped the identity in its
`IdentityDecorator`.

```php
// src/Controller/Api/PostsController.php
use Cake\Http\Exception\ForbiddenException;
use CakeDC\OAuthServer\OAuthServer;

public function publish(string $id): Response
{
    $token = OAuthServer::token($this->request);
    if ($token !== null && !$token->hasScope('content:publish')) {
        $error = new ForbiddenException('The token needs the content:publish scope.');
        $error->setHeaders([
            'WWW-Authenticate' => 'Bearer error="insufficient_scope", scope="content:publish"',
        ]);

        throw $error;
    }

    // ... publish the post
}
```

A `ValidatedToken` has `owner` (the person, with `subject` and `identity`), `client`, `resource`,
`scopes` and `hasScope()`. Scopes are computed at the moment of the check, so a scope removed from the
configuration or from the person's allowance disappears from live tokens at once.

The identity of an authenticated request is an `OAuthIdentity`. It behaves like the person's own identity
(`$identity['email']`, `getIdentifier()`) and adds the token:

```php
use CakeDC\OAuthServer\Identity\OAuthIdentity;

$identity = $this->Authentication->getIdentity();
if ($identity instanceof OAuthIdentity && $identity->hasScope('content:read')) {
    $token = $identity->getOAuthToken();
}
```

When `$this->Authentication->getIdentity()` returns an `IdentityDecorator` (with `cakephp/authorization`),
use `OAuthServer::token($this->request)`; it unwraps it for you.

A person who signed in with the browser session has no token. Decide for your routes whether session
requests may pass: `OAuthServer::token($request) === null` means "not a token request".

## In policies

Policies get the identity, not the request. Check scopes in the controller (as above) or in a middleware,
and keep policies about the person.

## Without a login for APIs

If a route is for tokens only, you can skip the session authenticators for it by building the service per
request:

```php
public function getAuthenticationService(ServerRequestInterface $request): AuthenticationServiceInterface
{
    $service = new AuthenticationService();
    $service->loadAuthenticator('CakeDC/OAuthServer.Token', ['resource' => 'https://example.com/api']);
    if (!str_starts_with($request->getUri()->getPath(), '/api/')) {
        $service->loadAuthenticator('Authentication.Session');
    }

    return $service;
}
```
