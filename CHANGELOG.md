# Changelog

## 1.0.0-beta1 (2026-10-16)

First release. An OAuth 2.1 authorization server for CakePHP 5 on top of cakedc/oauth-server.

- Requires CakePHP 5.1.10 or later and `cakephp/authentication` 3.3.6 or later: earlier releases have published
  security advisories (one of them an open redirect through the login's `redirect` parameter, the flow the
  consent page uses), and current Composer refuses to install them.
- Follows the core's review fixes. `/authorize` never redirects before the person signed in (a visitor gets the
  login with the same return address on `GET`, the plain error page on `POST`), and sends an error back to the
  client automatically only when an administrator registered it or the signed-in person approved it before.
  Otherwise the error page names the destination and offers a plain "Continue to ..." link: `CakeErrorPageRenderer`
  implements the core's `RedirectNoticeRendererInterface` and `templates/OAuth/error.php` gets `$notice` (a
  `RedirectNoticeView`, `null` on other error pages). An override of `error.php` that ignores `$notice` shows the
  plain page and never sends the person to the client.
- A remembered consent no longer answers for a public client with a loopback or private-scheme redirect URI
  (Claude Code connecting over loopback among them): the consent page is shown on every connection, with the new
  line "You approved this application before...". https clients and confidential clients are remembered as before.
- The consent and connections pages never headline a self-registered client by a name or a host it chose. The
  consent page uses `ConsentView::clientLabel()` (the host its answer goes to; "An application on this computer"
  for a private-use scheme) in the title, the heading and the "from" line, and shows `declaredName()` only as
  "It calls itself ..." with the name inside a `<q>` element. The connections page labels such a client by the
  hosts of its redirect URIs (`Client::webHosts()`), with "and an application on this computer" when it also has a
  private-use redirect. New public `CakeDC\OAuthServer\View\QuotedName::html()` prints a client-chosen name that
  way for template overrides. Overrides that print `client->name` or `clientHost()` in the heading of a
  dynamically registered client are spoofable: update them ([pages](docs/pages.md#variables)).
- Follows the core's last review fixes: a private-use scheme is shown with its colon (`claude.ai:`, so it cannot
  pass for a host), and the consent page of a self-registered application with a private-use redirect says "The
  request comes from an application on this computer" instead of repeating the fixed label as if it were a host.
  New translatable string, Spanish catalogue updated.
- `oauth client list` has a "Hosts" column (the web hosts of the redirect URIs, plus "An application on this
  computer" for a private-use redirect) and heads the name column "Name (declared)": a self-registered client's
  name is its own choice.
- Documentation: `forClient` examples identify the client by `clientId`, never by name; a confidential
  self-registered client with a remembered consent skips the consent page (only public ones always see it); the
  `saveConsent` outer-transaction limit applies to MySQL and MariaDB under REPEATABLE READ as well as PostgreSQL.
- `registration.allowPrivateSchemes` now defaults to `false` (the core's new default): dynamic registration and
  metadata documents accept https and loopback http redirect URIs only. Clients added with `oauth client add` may
  still use private-use schemes. The configuration example no longer enables it.
- Client names (`oauth client add`, dynamic registration) and personal token names follow the core's name rules:
  at least one visible character, no control, bidirectional or other invisible characters, lengths counted in
  characters. `oauth client add` prints the core's message and exits non-zero for such a name.
- `OrmStorage` implements the core's new `deleteCodesBySubject()` and `deleteCodesByClient()` (one `DELETE` of
  the unused codes each), so `oauth token revoke --subject` and `--client` and revoking a connection on the
  connections page also delete the codes not exchanged yet. It refuses a second client with the same `client_id`
  (insert or update) and passes the core's storage contract on SQLite, MySQL 8.4, MariaDB 11.8 and PostgreSQL 17.
- `OrmStorage::prune()` claims each unused client with one conditional `UPDATE` inside its transaction (after
  `SELECT ... FOR UPDATE` on MySQL, MariaDB and PostgreSQL) and deletes it only when the claim succeeds, so a client
  used or given a token after `oauth prune` selected it is kept with its token. `PruneLockTest` replays the race
  with two processes when `DB_URL` points at MySQL, MariaDB or PostgreSQL.
- New migration `20261017120000_AddOAuthCodesSubjectIndex.php`: an index on `oauth_authorization_codes (subject)`,
  as in the core's schema. Apply it the way you applied the first one: `bin/cake migrations migrate -p
  CakeDC/OAuthServer`, or copy it into your application's `config/Migrations` and run `bin/cake migrations
  migrate`. `oauth check` warns on the `Tables` line when it is missing, and its messages name both ways.
- The connections page shows a connection's grant (its newest unrotated refresh token), so a down-scoped refresh
  no longer makes it show less; a refresh keeps the grant on the new refresh token and narrows only the access
  token (documented in configuration and users).
- Rate limiting fails open when the Cake cache behind it fails, logging a warning on the `oauth` scope, and
  `/introspect` has its own counter, `rateLimit.introspect` (default `[600, 60]`), which the plugin passes through.
- `#[\SensitiveParameter]` on the plugin's parameters that carry secrets: `PluginConfig` settings (with `secret`
  and `registration.initialAccessToken`) and secret, and `OAuthTestTrait::withOAuthToken()`.
- The MCP bridge needs mcp/sdk 0.9 or newer (`mcpTokenValidator()` says so with a `LogicException`).
- `OrmStorage` no longer uses the core's internal `Support\Time`. The plugin still builds the core's internal
  `HttpResponder` to read the core's page policy (`OAuthServer::pageCsp()`) and to answer 503; it is internal to
  the core and used only within CakeDC packages.
- English and Spanish translations of the new texts.
- A broken `OAuthServer` configuration never takes the application down, on the web or the command line: the
  application's pages (the login included), `bin/cake` and migrations keep working, the plugin's routes are still
  connected (at the configured prefix and issuer when each is valid on its own) and answer 503 (JSON on the
  metadata, token, register, revoke and introspect endpoints; the application's error page on the consent and
  connections pages), a bearer token of this server gets 401 (a POST, PUT, PATCH or DELETE gets it, with
  cookies or without, while the resources, the issuer and `tokenPaths` can still be read; otherwise the CSRF
  middleware answers 403 first; with a `tokenPrefix` that is not a string, every bearer POST, PUT, PATCH or
  DELETE gets that 403), and each refusal logs the reason on the `oauth` scope. Any invalid setting counts, a wrong type included (a resource declared with a string used to break
  `bin/cake` with a `TypeError`), and so do invalid `users` and `tokenPaths` values. `oauth check` reports it.
- The Token authenticator reads no configuration when it is built: the resource, the paths and the server are
  resolved on the first request with a bearer token of this server's prefix, and a failure there (an undeclared
  `resource`, a root resource without `paths`, an invalid `paths`, a broken configuration) refuses that token with
  401 and logs why, instead of throwing on every request. `TokenAuthenticator::resolve()` (internal) is what
  `oauth check` uses to report it.
- `OAuthServer::csrfSkip()` skips CSRF for the client endpoints and, on the routes of a resource
  (`OAuthServer.tokenPaths` or the `$paths` argument override the paths), for two kinds of request: one with a
  bearer token of this server's prefix (`<tokenPrefix>_at_`, `<tokenPrefix>_pat_`), whatever cookies it carries,
  and one with no credential at all (no `Authorization` header, no cookie but the CSRF middleware's own, no HTTP
  Basic or Digest credentials, no `REMOTE_USER`). Only the prefix is read: the token is never looked up and the
  server is never built. A page on another site cannot make a browser attach an `Authorization` header without a
  CORS preflight approved with credentials, and with the Token authenticator first the session is never
  consulted for such a request. So a client whose token expired, was revoked, belongs to another resource or to
  a deactivated person gets the Token authenticator's 401 with `error="invalid_token"`, the signal to refresh or
  to sign in again, instead of the CSRF middleware's 403 (MCP Streamable HTTP sends every message as a POST),
  also when it keeps cookies (the CSRF cookie the middleware sets on any GET, which httpx in the MCP Python SDK
  sends back, or a load balancer's sticky cookie), and the first POST of an MCP client, without a token, reaches
  the endpoint's own 401 with `resource_metadata`, so discovery starts. A request without a token of this server
  that carries any other cookie, another `Authorization` scheme or another server's token gets the normal CSRF
  check. New setting `OAuthServer.csrfCookieName` (default `csrfToken`) names the CSRF cookie when the
  middleware's `cookieName` was changed. The consent and connections pages and the login page are never
  skipped, and neither is a request that was not routed yet; a login given as a URL array is also recognised on
  every other route to its action (a fallback route such as `/Users/login`). `csrfSkip()` never throws. The
  client endpoints are skipped with any configuration, a broken one included, because they are found where the
  plugin connected them; when the resources, the issuer or `tokenPaths` cannot be read nothing else is skipped
  and a warning goes to the `oauth` log, never the token.
- The Token authenticator has a `paths` option (default: the path of its resource) and refuses, with 401, a
  request that carries this server's token anywhere else. Both the request path and the static part of the
  template of the route that matched it must be within `paths`, so a route that starts with a placeholder
  (`/{tenant}/account/delete`) never receives the token through a URL that looks like the resource's
  (`/mcp/account/delete`), and a request that was not routed yet is refused. Routes of a resource need a
  static prefix within its paths.
- Subdirectory installs: the login redirect of the connections page carries the base path once.
- People tables keyed by a column other than `id` work: the identity reports the key as its identifier.
- With cakedc/users, applying the integration never fails: with an invalid `OAuthServer.users` setting, or a
  resource at the host root without paths, the Token authenticator is still registered first and refuses every
  token of this server, and `oauth check` fails on the `Users integration` line.
- With cakedc/users, cakedc/auth's one-time login authenticator (`CakeDC/Auth.OneTimeToken`) is replaced by
  `CakeDC/OAuthServer.UsersOneTimeToken`, which does not read the `token` parameter on the plugin's routes, so a
  refresh token sent to `/oauth/revoke` or `/oauth/introspect` is never looked up in the users table nor written
  to the query log. `oauth check` warns when another class is configured or `CakeDC/Users` is loaded after the
  plugin.
- `OAuthServer::rbacPermissions()` lists the controller's actions instead of `*`, so a future action does not
  inherit the bypass.
- `oauth check` builds the server the way the endpoints do on its `Configuration` line, so every setting that
  makes them answer 503 fails the check (an unknown `users` or `consent` key, a non-string `users.resource`, a
  wrongly typed `services` entry used to pass with exit code 0).
- The 503 of the machine endpoints carries `Retry-After: 300` and their usual CORS headers, and a CORS preflight
  gets the usual 204, so browser clients see the 503.
- `oauth check` fails on its `Authenticators` line when a session, cookie (remember-me) or form authenticator
  comes before the Token authenticator (it used to warn about the session one only): `csrfSkip()` lets bearer
  requests of this server through without looking the token up, and only the Token authenticator first keeps a
  session cookie sent with a made up token from being used.
- `oauth check` also warns about a missing CSRF middleware, checks that a string login URL routes, and no longer accuses subdirectory installs of an `App.base` mismatch
  when the base is detected at runtime. It fails when the CSRF callback also skips session routes (it probes the
  consent and connections pages, `/` and the login), recognises `SessionCsrfProtectionMiddleware`, fails when the
  CSRF or authentication middleware runs before `RoutingMiddleware` while a Token authenticator of this plugin is
  loaded and warns when none is (a new `Middleware` line), fails when another
  route takes `<prefix>/token` (a new `Routes` line), warns when the rate limit cache is an `Array` or `Null`
  engine, fails when a Token authenticator would refuse every token, inspects the connection of the plugin's
  tables instead of `default`, and checks every column and unique key of the migration instead of one column.
- Lookups by id (`findTokenById()`, `findTokensByFamily()`, `findClientById()`) answer nothing without a query
  for an id that is not shaped like a UUID, so a malformed `family_id` or `token_id` on the connections page
  (invalid UTF-8 failed the query on PostgreSQL with a 500 and the SQL in the log) is simply ignored.
- The entities are closed to mass assignment (`'*' => false`; `OrmStorage` passes `accessibleFields`) and hide
  `secret_hash`, `code_hash` and `token_hash` from `toArray()` and JSON.
- `RequestPaths::routePath()` treats a hand-built route template without a leading slash as the root instead of
  its first character.
- PHPStan runs with a bootstrap of its own, so an analysis no longer runs the migrations nor leaves a SQLite file
  in `tests/test_app/tmp`.
- Documentation: the cakedc/users plugin order and why, the database user note of the security checklist, the
  output of `oauth client add`, the nginx PHP location and why the subdirectory rewrite works, test tokens having
  no client, application CSP middleware on the plugin's pages, a `loginUrl` for the `Form` authenticator, why
  `tokenPaths ['/']` costs every other sign-in form its login CSRF protection, MCP and REST clients with a cookie
  jar, and that IntegrationTestTrait's `session()` sends no cookie (`cookie(session_name(), ...)` models a
  browser).
- Deployment docs: set `OAuthServer.issuer` or `App.fullBaseUrl` explicitly; the skeleton otherwise fills it
  from the `Host` header.
- Installation docs and README: while the plugin and the core are betas, install both with
  `composer require cakedc/cakephp-oauth-server:^1.0@beta cakedc/oauth-server:^1.0@beta` (Composer reads
  stability flags from the root package only), or set `"minimum-stability": "beta"` with `"prefer-stable": true`.
- `docs/index.md` lists `QuotedName` in the public API.
- Public API boundary: `PluginConfig`, `ServerFactory`, the template renderers, `UsersIntegration`,
  `PluginMessagesLoader`, `UtcDateTimeType`, `RbacPermissionsProvider`, the event dispatcher and the logger are
  `@internal`, as are `OAuthServer::pageCsp()` and `OAuthServer::forRequest()`.
- Token paths fail closed on `%2F`, empty segments and dot segments. With cakedc/users, a root resource without
  explicit paths makes the integration's Token authenticator refuse every token of this server (it is never
  accepted on every route by accident) and `oauth check` fails on it; the application keeps working.
- Routes for the metadata document and the authorize, token, register, revoke, introspect and connections
  endpoints, handled by `OAuthController`.
- ORM storage (`OrmStorage`) and one migration for `oauth_clients`, `oauth_authorization_codes`,
  `oauth_tokens` (with `family_started_at`) and `oauth_consents`; CHAR(36) ids and `utf8mb4_bin` on MySQL
  and MariaDB.
- Configuration under `OAuthServer`: the core's keys plus `userProvider`, `login`, `consent`, `connections`,
  `users` and `services`, and `rateLimit.cache`.
- `OrmUserProvider` and `SessionUserContext`: people from an ORM table with a finder, `canAuthorize`,
  `scopes` and `forClient` callbacks, sign-in through the application's own login.
- `CakeDC/OAuthServer.Token` authenticator for `cakephp/authentication` (`OAuthIdentity`,
  `OAuthServer::token()`), also registered as `OAuthServerToken` for `cakedc/users`.
- Consent, connections and error pages as Cake templates, overridable under
  `templates/plugin/CakeDC/OAuthServer`, with an optional application layout and an extended
  Content-Security-Policy (`OAuthServer::pageCsp()`).
- `cakedc/users` integration: users table, display field, login route, authenticator and one RBAC rule
  through `RbacPermissionsProvider` (`OAuthServer::rbacPermissions()`).
- Commands: `oauth client add`, `oauth client list`, `oauth client revoke`, `oauth token revoke`
  (`--subject`, `--client`, `--consents`), `oauth prune` and `oauth check`.
- Events on Cake's event manager: `OAuthServer.tokenIssued`, `OAuthServer.tokenRevoked`,
  `OAuthServer.consentGranted`, `OAuthServer.clientRegistered`, `OAuthServer.refreshTokenReused` and
  `OAuthServer.authorizationDenied`.
- `OAuthTestTrait` for integration tests.
- English and Spanish translations (`oauth_server` domain).
- Documentation in `docs/`.

### Known issues for 1.0.0

Found by the pre-release review and left for 1.0.0, not fixed in this beta:

- The `header` option of the Token authenticator is not honoured by `OAuthServer::csrfSkip()`, which always reads
  `Authorization` (RFC 6750 defines no other header); the option will be removed or `csrfSkip()` will follow it.
- Three overlapping path settings: the Token authenticator's `paths` defaults to the path of its resource and
  ignores `OAuthServer.tokenPaths`, and `csrfSkip()` ignores `OAuthServer.users.paths`. A mismatch fails closed
  (401 or 403); until they are unified, set the same list in every place.
- A bearer token of this server sent to the plugin's own `token`, `revoke` or `introspect` endpoint is challenged
  by the Token authenticator (401, outside the token paths) before the core answers as RFC 6749, 7009 and 7662
  say, which confuses clients whose HTTP layer adds `Authorization` to every request.
- Bootstrapping the plugin instantiates every configured log engine (to see whether one receives the `oauth`
  scope), where CakePHP builds them lazily; an engine that depends on something configured later fails at boot.
- A refresh token (`<prefix>_rt_`) presented as a bearer token is passed on silently to the next authenticator
  instead of being refused with 401. It is never accepted and never skips CSRF.
- `OAuthServer::csrfSkip()` skips CSRF for a bearer token of this server's prefix without validating it. One
  scenario stays open, and only on a misconfigured application: a page on another site makes a signed in
  browser send a made up bearer token with its session cookie. That needs your application to approve the
  site's CORS preflight with credentials (which already gives the site everything CSRF protects). The request
  then runs as the session user when a session can still run it: a stateful authenticator (session, cookie or
  form) comes before the Token authenticator, there is no Token authenticator on a token path, the Token
  authenticator reads a `header` other than `Authorization` (`csrfSkip()` only reads `Authorization`), or an
  Environment authenticator comes first. `oauth check` fails on the order at every token path and warns on
  another header.
- Behaviour change for hosts with their own bearer clients (JWT, API keys) on the resource routes: a request
  with a bearer token that is not this server's now gets CSRF's 403 where the previous build skipped it. Keep
  skipping them with `OAuthServer::csrfSkip($request) || <your own condition>`. Clients that still hold tokens of
  an old `tokenPrefix` get 403 rather than 401 until they sign in again.
- `OAuthServer.csrfCookieName` cannot be the session cookie's name (`Session.cookie`, else `session_name()`): it
  is an invalid setting. It would let session requests on the token paths skip CSRF.
- A string `OAuthServer.login.url` is also matched by the route it resolves to, so aliases through fallback
  routes (`/Pages/login`) are never skipped, like with a URL array.
- From the core: concurrent refreshes with the same refresh token can revoke the whole family (the grace window
  absorbs a retry after a lost response, not parallel refreshes). Clients must send one refresh at a time per
  token.
- Public API to settle before 1.0.0: `OAuthServer::pageCsp()` and `OAuthServer::forRequest()` are public methods
  marked `@internal` on the facade (to move to an internal class); `OAuthController` is declared neither public nor
  internal; the plugin's routes have no names (`_name`) to link to; `OAuthServer.services` (clock, transport,
  dns) is a test seam inside the public configuration and is not supported; a Token authenticator protects one
  resource and an authentication collection cannot hold two with the same alias, so the cakedc/users integration
  protects a single resource.
