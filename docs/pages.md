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

### Variables

| Template | Variable | Type |
| --- | --- | --- |
| `consent.php` | `$consent` | `CakeDC\OAuth\Server\View\ConsentView` |
| `connections.php` | `$connections` | `CakeDC\OAuth\Server\View\ConnectionsView` |
| `error.php` | `$error` | `CakeDC\OAuth\Server\Exception\OAuthException` |

Useful members of `ConsentView`: `client`, `owner` (with `displayName`), `resource` (with `name`), `scopes`
(scope name to description, granted scopes only), `offlineAccess`, `redirectUri`, `formAction`, `fields`,
and the methods `clientHost()`, `redirectHost()`, `isUnverified()` and `isLoopbackOnly()`.

Useful members of `ConnectionsView`: `owner`, `connections` (each with `familyId`, `client`, `resource`,
`scopes`, `connectedAt`, `lastUsedAt`), `personalTokens`, `creatable`, `personalTokensEnabled`,
`newToken`, `error`, `formAction`, `formToken`, `maxDays` and `resourceName($identifier)`.

Use the values as the core computed them. In particular name a client created from a metadata document by
`clientHost()` (the host of its `client_id`), never by `client->name`, which the client chose itself, and
print the "unverified" and loopback notices. Print `offlineAccess` as is. The shipped templates show how.

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

## Translations

Interface strings are English in the templates and go through `__d('oauth_server', ...)`. The plugin ships
`resources/locales/oauth_server.pot` and a Spanish translation, `resources/locales/es/oauth_server.po`.

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
