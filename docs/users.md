# Users

The core library needs two things from your application: a way to find people (`UserProviderInterface`)
and a way to know who is signed in (`UserContextInterface`). The plugin supplies both:

- `CakeDC\OAuthServer\Identity\OrmUserProvider` finds people in an ORM table.
- `CakeDC\OAuthServer\Identity\SessionUserContext` reads the signed-in person from the request.

The interfaces are described in the core's
[users](https://github.com/CakeDC/oauth-server/blob/1.x/docs/users.md) page.

## OrmUserProvider

With no configuration it looks people up in the `Users` table with the `active` finder. Settings, all
under `OAuthServer.userProvider` (see [configuration](configuration.md#userprovider)):

```php
'userProvider' => [
    'table' => 'Users',            // ORM alias
    'finder' => 'active',          // a finder the table must have
    'displayField' => 'email',     // shown on the consent page; default: the table's display field
    'canAuthorize' => ...,
    'scopes' => ...,
    'forClient' => ...,
],
```

Rules that follow from the code:

- The table needs a single column primary key, called `id` or anything else (`user_id`, `member_id`). The
  subject of a token is that key as a string, and the identity handed to your callbacks reports it as its
  identifier.
- A person is found only when the finder finds them, so a deactivated person (the `active` finder no
  longer returns them) stops working at once: the consent page asks them to sign in again and their
  existing tokens stop validating.
- The key is compared exactly. A numeric key must be written in digits, and a case insensitive
  collation or a loose comparison cannot make another spelling resolve to the same person.
- The finder has to exist. `bin/cake oauth check` reports `has no finder "active"` when it does not. A
  quick one:

  ```php
  // src/Model/Table/UsersTable.php
  public function findActive(SelectQuery $query): SelectQuery
  {
      return $query->where([$this->aliasField('active') => true]);
  }
  ```

### canAuthorize

Decides whether this person may give this client access to this resource. It runs on the
requests to `/authorize` (showing the page and receiving the decision). It must return a `bool`
(anything else throws `UnexpectedValueException`).

```php
use Authentication\IdentityInterface;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Resource\ProtectedResource;

'canAuthorize' => function (IdentityInterface $user, Client $client, ProtectedResource $resource): bool {
    // Only editors and admins may connect an assistant to the content API.
    return in_array($user['role'], ['editor', 'admin'], true);
},
```

When it returns `false`, the client receives `access_denied` and an `OAuthServer.authorizationDenied`
event is dispatched with the reason `not_allowed`.

`canAuthorize()` is not asked again after `/authorize`. Tokens already issued keep working when the
policy changes, so after a change revoke the tokens ([below](#cutting-a-person-off)).

### scopes

Limits the scopes this person may hold. It receives the identity and the resource and returns `null`
(no extra limit, the resource's scopes apply) or a list of scope names.

```php
'scopes' => function (IdentityInterface $user, ProtectedResource $resource): ?array {
    return match ($user['role']) {
        'admin' => null,
        'editor' => ['content:read', 'content:write'],
        default => ['content:read'],
    };
},
```

The result is applied when tokens are used, on every refresh and code exchange, so a demotion narrows
what existing grants can do. An empty list means no access at all.

### forClient

Gives a client an identity of its own, for the client credentials grant (a program acting for itself).
Return an identity (an array or entity), a `ResourceOwner`, or `null` or `false` for none. Without it the
grant answers `unauthorized_client`.

```php
'forClient' => function (Client $client, ProtectedResource $resource): mixed {
    if ($client->name !== 'Nightly import') {
        return null;
    }

    return ['id' => 'service-import', 'role' => 'service'];
},
```

The token's subject is the client's `client_id` and its subject type is `client`, so it never passes for
a person. Nobody consents for them: the consent page only serves people. To restrict their scopes,
register the client with a `scopes` list (`bin/cake oauth client add` has `--scope`, and see
[commands](commands.md#oauth-client-add)).

## A custom provider

When people do not live in an ORM table (or you want full control), write a class that implements
`CakeDC\OAuth\Server\Owner\UserProviderInterface` and set `className`:

```php
// src/OAuth/MyUsers.php
namespace App\OAuth;

use Authentication\Identity;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\UserProviderInterface;
use CakeDC\OAuth\Server\Resource\ProtectedResource;

class MyUsers implements UserProviderInterface
{
    public function __construct(private array $settings)
    {
    }

    public function findBySubject(string $subject): ?ResourceOwner
    {
        $person = MyDirectory::find($subject);

        return $person === null ? null : new ResourceOwner($subject, $person['name'], new Identity($person));
    }

    public function canAuthorize(ResourceOwner $owner, Client $client, ProtectedResource $resource): bool
    {
        return true;
    }

    public function scopesFor(ResourceOwner $owner, ProtectedResource $resource): ?array
    {
        return null;
    }

    public function forClient(Client $client, ProtectedResource $resource): ?ResourceOwner
    {
        return null;
    }
}
```

```php
'userProvider' => ['className' => \App\OAuth\MyUsers::class],
```

A class name is built with the `userProvider` settings array as its only argument. You can also pass an
object instead of a class name. A class that does not implement the interface throws
`InvalidArgumentException` (`"OAuthServer.userProvider.className" must implement UserProviderInterface.`).
`bin/cake oauth check` reports `custom user provider` and does not inspect it.

## How the signed-in person is found

`SessionUserContext::currentOwner()` reads the identity from the request attribute that your
authentication service reports (the `identity` attribute unless you renamed it; with no authentication
service, `OAuthServer.login.identityAttribute`). It takes the identity's identifier, or the primary key column of the users table
for a plain array or entity, and asks the provider for the person again with `findBySubject()`. So an inactive person is
treated as signed out and gets the login page.

It returns nobody, and so the login page, when:

- the identity was established by a stateless authenticator (a bearer token, HTTP Basic, JWT, ...),
- the request is an impersonation, or
- the identity is an `OAuthIdentity` (a request authenticated with an OAuth token).

A bearer token is never a browser login: it must not approve clients or mint tokens.

With a users table keyed by another column than `id`, make your authentication service build identities
that know their identifier, for example `'identityClass' => fn($data) => new Identity($data, ['fieldMap' =>
['id' => 'user_id']])`, so `getIdentifier()` returns the key. `OAuthTestTrait` reads the same key column from
an entity or an array you pass to `oauthTokenFor()`.

## The login URL and the redirect parameter

An anonymous person is redirected to `OAuthServer.login.url` with the return address appended as
`?redirect=<encoded address>`:

```php
'login' => [
    'url' => ['plugin' => null, 'controller' => 'Users', 'action' => 'login'],
    'redirectParam' => 'redirect',
],
```

`url` is anything `Router::url()` takes: a string, a route array or a named route (`['_name' => 'login']`).
For an array the plugin fills `plugin` and `prefix` with `false` unless you set them, so the link does not
inherit the OAuth plugin from the current request. `redirectParam` is the query parameter your login
reads (`redirect` is the `cakephp/authentication` default).

Your login must send the person back to that address once they sign in and must only follow relative
addresses of your own site. With `cakephp/authentication`'s form login this is
`$this->Authentication->getLoginRedirect()`.

## Cutting a person off

`SessionUserContext` and the user provider decide who is active, so deactivating an account needs no
revocation: its tokens stop validating immediately. In every other case (account deleted for good, a
policy change, a suspected takeover) revoke tokens and remembered consents:

```bash
bin/cake oauth token revoke --subject 42 --consents
```

`--consents` also deletes the person's remembered consents, so a client they approved before cannot skip
the consent page. From code, it is `revokeAllForSubject()` and `deleteConsentsBySubject()`:

```php
use CakeDC\OAuthServer\OAuthServer;

$server = OAuthServer::server();
$revoked = $server->tokenRevoker()->revokeAllForSubject('42');
$deleted = $server->storage()->deleteConsentsBySubject('42');
```
