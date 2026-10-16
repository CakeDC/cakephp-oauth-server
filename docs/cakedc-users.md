# Using it with cakedc/users

With [cakedc/users](https://github.com/CakeDC/users) the plugin needs almost no setup: the users table,
the login, two-factor and social login, and the RBAC rules are picked up for you.

## Plugin order

Load `CakeDC/Users` first:

```php
// src/Application.php
public function bootstrap(): void
{
    parent::bootstrap();
    $this->addPlugin('CakeDC/Users');
    $this->addPlugin('CakeDC/OAuthServer');
}
```

The login, the Token authenticator and the RBAC rule work in either order (cakedc/users merges its configuration
over what the plugin wrote and keeps the authenticator in front). One step needs this order: replacing the
one-time login authenticator ([one-time login links](#one-time-login-links)), because cakedc/users resets its
class name when it loads its configuration after the plugin. `bin/cake oauth check` warns when that step did not
happen.

## What happens automatically

When `CakeDC/Users` is loaded, `OAuthServerPlugin::bootstrap()` applies
`CakeDC\OAuthServer\Integration\UsersIntegration`:

| What | Value used |
| --- | --- |
| People table | `Users.table` from your cakedc/users configuration, else `CakeDC/Users.Users` (override with `userProvider.table`) |
| Finder | `active` (cakedc/users defines it) |
| Name on the consent page | `username` (override with `userProvider.displayField`) |
| Login | `['plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => 'login', 'prefix' => false]` (override with `login.url`) |
| Authenticator | `Auth.Authenticators.OAuthServerToken`, put first, with `className` `CakeDC/OAuthServer.OAuthServerToken` and `skipTwoFactorVerify` `true`. It gets `resource` from `OAuthServer.users.resource` when you set it, and `paths` from `OAuthServer.users.paths`, else `OAuthServer.tokenPaths`, else the path of the resource |
| One-time login | `Auth.Authenticators.OneTimeToken.className` set to `CakeDC/OAuthServer.UsersOneTimeToken` when it is cakedc/auth's `CakeDC/Auth.OneTimeToken`: the same authenticator, except that it does not read `token` on the plugin's routes ([one-time login links](#one-time-login-links)) |
| RBAC rules | `Auth.RbacPolicy.adapter.permissions_provider_class` set to `CakeDC\OAuthServer\Integration\RbacPermissionsProvider`, unless your application already set its own provider |

Notes:

- The authenticator class is `OAuthServerToken`, not `Token`, because an authentication collection aliases
  authenticators by class name and cakedc/users already has a `Token` authenticator. Loading the plugin's
  `CakeDC/OAuthServer.Token` next to it fails with "The `Token` alias has already been loaded". Use
  `OAuthServerToken` with cakedc/users and `Token` otherwise. They are the same class.
- The authenticator is added first so a session cookie sent along with a revoked or made up bearer token
  cannot make the request run as the session user. Keep it first: `OAuthServer::csrfSkip()` skips CSRF for
  bearer requests of this server without looking the token up, and `bin/cake oauth check` fails when a session,
  cookie or form authenticator comes before it.
- If `Auth.Authenticators.OAuthServerToken` is already set, the plugin leaves it alone.
- Applying the integration never fails, so an invalid setting cannot take your login down. With an invalid
  `OAuthServer.users` (or any other invalid `OAuthServer` setting), or a resource at the host root without
  paths, the authenticator is still registered first and refuses every token of this server with 401, and
  `bin/cake oauth check` fails on its `Users integration` line with the setting to fix.
- Set `OAuthServer.users.resource` to the resource your API routes belong to. Without it the authenticator
  validates tokens of the default resource. Either way a token works only on the routes of its resource,
  whose path and route template are below the resource's path (`/api` for `https://example.com/api`): on
  cakedc/users pages such as `/profile` or `/logout` a request carrying this server's token is refused with
  401 and never reaches the controller. Inside the path,
  checking scopes is your job: `OAuthServer::token($request)->hasScope('content:read')`. A resource at the
  host root (the default resource included) needs `OAuthServer.users.paths` (or `OAuthServer.tokenPaths`) set explicitly. See
  [protecting-apis](protecting-apis.md).

```php
// config/app_local.php
'OAuthServer' => [
    'resources' => [
        'https://example.com/api' => [
            'name' => 'Example API',
            'scopes' => ['api:read' => 'Read your data', 'api:write' => 'Change your data'],
            'implies' => ['api:write' => ['api:read']],
            'defaultScopes' => ['api:read'],
        ],
    ],
    'users' => ['resource' => 'https://example.com/api'],
],
```

## One-time login links

cakedc/users loads cakedc/auth's `OneTimeToken` authenticator, which reads a `token` parameter from the query or
the body of **every** request and looks it up in the users table. RFC 7009 and RFC 7662 call the parameter of
`/oauth/revoke` and `/oauth/introspect` `token` as well, so a refresh token sent there would be compared with the
users' login tokens and, with query logging on (debug, DebugKit, a connection with `log => true`), written in
clear to the query log.

The integration therefore replaces `CakeDC/Auth.OneTimeToken` with `CakeDC/OAuthServer.UsersOneTimeToken`, the
same authenticator except that it ignores the plugin's routes. One-time login links keep working everywhere
else. It does this only when the class is cakedc/auth's own and `CakeDC/Users` is loaded first. If you use your
own one-time login class, make it skip the plugin's routes (`$request->getParam('plugin') === 'CakeDC/OAuthServer'`)
and keep query logging off in production; `oauth check` warns while the class is not the plugin's.

## Two-factor and social login

People sign in at your login, so everything cakedc/users puts in front of it (two-factor verification and
social login) applies to the consent page too. The authorize request waits at the login and
resumes at the return address afterwards. The token authenticator skips the two-factor check
(`skipTwoFactorVerify`), because a token carries no second factor of its own: the person already passed it
when they approved the client.

## When you override the authenticators or the permissions wholesale

The integration writes into `Configure` while the plugin bootstraps. If your own configuration then
replaces `Auth.Authenticators` or provides a different permissions provider, add the pieces by hand.

Authenticators, in the file where you define them (the token one comes first):

```php
// config/users.php
'Auth.Authenticators' => [
    'OAuthServerToken' => [
        'className' => 'CakeDC/OAuthServer.OAuthServerToken',
        'skipTwoFactorVerify' => true,
        'resource' => 'https://example.com/api',
    ],
    // ... your other authenticators (Session, Form, ...) follow
    'OneTimeToken' => [
        // Not cakedc/auth's CakeDC/Auth.OneTimeToken: see "One-time login links".
        'className' => 'CakeDC/OAuthServer.UsersOneTimeToken',
        'skipTwoFactorVerify' => true,
    ],
],
```

RBAC rules, when you keep your own provider or when `config/permissions.php` is the only source:

```php
// config/permissions.php
use CakeDC\OAuthServer\OAuthServer;

return [
    'CakeDC/Auth.permissions' => array_merge(OAuthServer::rbacPermissions(), [
        ['role' => '*', 'controller' => 'Pages', 'action' => 'home', 'bypassAuth' => true],
        // ... your rules
    ]),
];
```

`OAuthServer::rbacPermissions()` returns one rule: `role` `*`, plugin `CakeDC/OAuthServer`, controller
`OAuth`, action `['metadata', 'authorize', 'token', 'register', 'revoke', 'introspect', 'connections']`,
`bypassAuth` `true`. The OAuth endpoints decide access themselves (the consent and connections pages require a
session login, the token endpoints authenticate the client), so there is one rule for all of them instead of one
per action. The actions are listed instead of `*`, so an action added to the controller later does not inherit
the bypass. Rules you write in `Configure` are lost when cakedc/auth
loads `config/permissions.php`, which is why the integration uses a provider class
(`RbacPermissionsProvider`, which puts the OAuth rule first and then your file's rules).

## Using RBAC to decide who may authorize

The bypass rule only opens the endpoints. To decide which people may connect which clients, use
`canAuthorize` ([users](users.md#canauthorize)) and any rule you like, for example the person's role:

```php
'canAuthorize' => fn (IdentityInterface $user, Client $client, ProtectedResource $resource): bool
    => in_array($user['role'], ['admin', 'editor'], true),
```

## What oauth check says

With `CakeDC/Users` loaded, `bin/cake oauth check` runs an `RBAC` line that asks cakedc/auth whether an
anonymous request reaches the token endpoint:

| Result | Meaning |
| --- | --- |
| `PASS` `RBAC lets the OAuth endpoints through` | The rule is in place |
| `FAIL` `RBAC denies the OAuth endpoints; add OAuthServer::rbacPermissions() to config/permissions.php` | Add the rule as shown above |
| `WARN` `cakedc/auth is not installed` | Nothing to inspect |
| `WARN` `the RBAC adapter is not a cakedc/auth Rbac; its rules were not inspected` | You use your own adapter; make sure it lets `CakeDC/OAuthServer` `OAuth` through |

Without `CakeDC/Users` the line says `cakedc/users is not loaded`.
