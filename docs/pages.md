# Pages

The plugin renders three pages with Cake views: the consent page (`consent`), the connections page
(`connections`) and an error page (`error`). The core decides what each page shows and which headers it
sends; the templates only draw it. What the pages contain and why is described in the core's
[pages](https://github.com/CakeDC/oauth-server/blob/1.x/docs/pages.md).

The plugin's templates are in `templates/OAuth/` and its own layout is `templates/layout/oauth.php`
(`CakeDC/OAuthServer.oauth`): a small page with inline CSS and no scripts.

## Overriding a template

Copy the plugin's file into your application under `templates/plugin/CakeDC/OAuthServer/`, keeping the path:

```
templates/plugin/CakeDC/OAuthServer/OAuth/consent.php
templates/plugin/CakeDC/OAuthServer/OAuth/connections.php
templates/plugin/CakeDC/OAuthServer/OAuth/error.php
templates/plugin/CakeDC/OAuthServer/layout/oauth.php
```

Cake picks up your copy automatically. Override only what you need.

Templates render with your application's `AppView`, so its helpers are available. After a render on the
command line, `CakeTemplateRenderer` leaves a `Router` request set.

### Variables

| Template | Variable | Type |
| --- | --- | --- |
| `consent.php` | `$consent` | `CakeDC\OAuth\Server\View\ConsentView` |
| `connections.php` | `$connections` | `CakeDC\OAuth\Server\View\ConnectionsView` |
| `error.php` | `$error` | `CakeDC\OAuth\Server\Exception\OAuthException` |
| `error.php` | `$notice` | `CakeDC\OAuth\Server\View\RedirectNoticeView` or `null` |

Useful members of `ConsentView`: `client`, `owner` (with `displayName`), `resource` (with `name`), `scopes`
(scope name to description, granted scopes only), `offlineAccess`, `redirectUri`, `formAction`, `fields`,
`approvedBefore`, and the methods `clientLabel()`, `declaredName()`, `clientHost()`, `redirectHost()`,
`isUnverified()` and `isLoopbackOnly()`.

Useful members of `ConnectionsView`: `owner`, `connections` (each with `familyId`, `client`, `resource`,
`scopes`, `connectedAt`, `lastUsedAt`), `personalTokens`, `creatable`, `personalTokensEnabled`,
`newToken`, `error`, `formAction`, `formToken`, `maxDays` and `resourceName($identifier)`. A connection's
`scopes` are its grant (those of its newest refresh token that was not rotated yet), so a refresh that asked
for less does not make the page show less.

Use the values as the core computed them. The shipped templates show how; when you write your own, keep these
rules:

- **Name the client with `clientLabel()`.** It is the name of a client an administrator registered, the host of
  the `client_id` of a metadata document client, and the host the answer goes to for a self-registered (dynamic)
  client. It is empty for a self-registered client whose answer goes to a private-use scheme (anyone can claim
  any scheme, `claude.ai:` included): show a fixed text then, as the plugin does with "An application on this
  computer". Never headline a self-registered client by `client->name` or by `clientHost()` of a redirect URI it
  merely listed: both are its own choice.
- **The "from" line** uses `clientHost()`, or `redirectHost()` when it is empty, except for a self-registered
  client with a private-use redirect, which gets the core's `consent.fromLocal` text ("The request comes from an
  application on this computer. Your answer is sent to ..."): the scheme says only where the answer goes, and
  `redirectHost()` prints it with its colon (`claude.ai:`).
- **Show `declaredName()` only as a quote.** When it is not `null` (a self-registered client whose name differs
  from its label), print it as an unverified secondary line with the name inside a `<q>` element, never between
  quote characters, so a name such as `Claude". Verified publisher. "` cannot close the quote and go on as if the
  server were speaking. `CakeDC\OAuthServer\View\QuotedName::html($template, $name)` does it: it escapes both
  and puts the name in `<q>` at the `{0}` placeholder (or after the text when a translation dropped it):

  ```php
  <?= QuotedName::html(
      __d('oauth_server', 'It calls itself {0}. Anyone can choose that name.', QuotedName::PLACEHOLDER),
      $consent->declaredName(),
  ) ?>
  ```

- **Print the notices**: `isUnverified()` (the client registered itself), `isLoopbackOnly()` (any program on
  this computer can receive the answer) and `approvedBefore` (a remembered consent covers the request, but the
  client's identity cannot be confirmed: a public client with a loopback or private-scheme redirect is asked
  every time). Print `offlineAccess` as is.
- **On the connections page**, name a self-registered client by the hosts of its redirect URIs
  (`client->webHosts()`), with the fixed text when it has none and "and an application on this computer" when it
  also has a private-use redirect (`client->hasNonWebRedirect()`); its name, again, only as a `<q>` quote.

### The error page and untrusted clients

When a request fails in a way the client should hear about, the core sends the person back to the client only
when it trusts the redirect URI: a client an administrator registered, or one this person approved before. For a
self-registered or metadata document client nobody vouched for, it shows the error page instead, and `error.php`
gets `$notice` (a `RedirectNoticeView`; `null` on every other error page). Print what the shipped template prints:
the destination (`$notice->redirectHost()`, the scheme for a private-use URI) and a plain link to
`$notice->continueUrl` with `rel="noreferrer"`. Never follow it for the person: no script, no meta refresh, no
`Location`. A template of yours that ignores `$notice` shows the plain error page, and the person is not sent back
to the client at all.

Nothing is redirected before the person is signed in: a visitor gets the login first (`GET`) or the plain error
page (`POST`), and the request is checked again after the login.

### Forms and CSRF

Cake's CSRF protection stays on the consent and connections forms. Build the forms with `FormHelper`
(`$this->Form->create(null, ['url' => ...])` adds the token) or include `_csrfToken` yourself. A hand
written `<form>` without the token gets a 403.

The consent form must post:

- every entry of `$consent->fields` as a hidden input (these include `consent_token`),
- a `decision` value: `approve` or `deny` (the buttons).

The connections forms must post:

- `form_token` with `$connections->formToken`,
- `action`: `revoke_connection` (with `family_id`), `revoke_token` (with `token_id`) or `create_token`
  (with `name`, `resource`, `days` and one `scope:<name>` checkbox per scope; value `1`).

Print the hidden inputs with `h()` on both name and value. Scope names may contain dots, so print the
scope checkboxes by hand as `<input type="checkbox" name="scope:content.read" value="1">`; `FormHelper`
would turn dots into brackets. This relies on the raw request body, which PHP-FPM provides for urlencoded
POSTs.

### Titles

The shipped templates assign an already escaped title with `$this->assign('title', h(...))`. An application
layout may therefore print `$this->fetch('title')` raw. Do the same in templates you write.

## Using your own layout

`consent.layout` and `connections.layout` choose the layout:

```php
'consent' => ['layout' => 'default'],
'connections' => ['enabled' => true, 'layout' => 'default'],
```

`null` (the default) is the plugin's `CakeDC/OAuthServer.oauth`, `false` renders the template alone and a
string is a layout of your application. The error page uses the consent layout.

The plugin's controller does not set the variables your own controllers set for your layout (a menu, the
current user, ...). A layout that depends on them fails or looks empty; use a small dedicated layout
instead of `default` in that case.

### Content-Security-Policy

The pages keep the core's headers: `Cache-Control: no-store`, `X-Frame-Options: DENY`, a restrictive
`Content-Security-Policy`, `Referrer-Policy: no-referrer`. When you set an application layout, the plugin
extends the policy with `style-src 'self' 'unsafe-inline'`, `img-src 'self' data:` and `font-src 'self'`, so
the layout's stylesheets, images and fonts of your own site load. It never touches `script-src`,
`frame-ancestors`, `base-uri` or `X-Frame-Options`. So layout scripts do not run on these pages: design
the layout to work without JavaScript.

`OAuthServer::pageCsp(bool $connections = false)` returns the policy the controller applies (`null` when
the page uses the plugin's own layout). Use it if you render the pages yourself.

A Content-Security-Policy middleware of your application runs after the controller and changes this header.
Cake's `CspMiddleware` adds its policy next to the page's (`withAddedHeader()`): browsers enforce both, so the
pages keep `frame-ancestors 'none'` but lose what your policy does not allow (inline styles, for example). A
middleware that sets the header with `withHeader()` replaces the page's policy and drops `frame-ancestors
'none'` and the other restrictions. Skip such a middleware on the plugin's routes, or keep the header when one is
already set.

## Translations

Interface strings are English in the templates and go through `__d('oauth_server', ...)`. The plugin ships
`resources/locales/oauth_server.pot` and a Spanish translation, `resources/locales/es/oauth_server.po`. A
test checks that every message the templates use is in both files.

Keep the `{0}` placeholder in a translation of "It calls itself {0}. Anyone can choose that name.": the name goes
there inside its `<q>` element (a translation without it gets the name appended).

To translate to another language, or to change a text, copy the file into your application, for example
`resources/locales/fr/oauth_server.po`, and translate the `msgstr` values. Your files are loaded on top of
the plugin's, so you only need the strings you change. Cake's usual locale setup applies
(`I18n::setLocale()` or `App.defaultLocale`).

Scope descriptions come from your configuration and are passed through `__()` (the default domain) when
the pages render. Translate them in your own `resources/locales/<lang>/default.po`; the English text of the
description is the message id:

```php
'scopes' => ['content:read' => 'Read your posts'],
```

```
msgid "Read your posts"
msgstr "Leer tus publicaciones"
```
