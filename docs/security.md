# Security

The security model (what the server protects against, RFC 9700 item by item, refresh token rotation and
reuse detection, SSRF protections for metadata documents, secrets at rest) is the core's. Read it in
[security](https://github.com/CakeDC/oauth-server/blob/1.x/docs/security.md). The plugin wraps the core
and never relaxes what it enforces. This page lists what the plugin adds and what only you can do.

## What the plugin adds

- **Cake's CSRF stays on the consent and connections forms.** By `OAuthServer::csrfSkip()` only the token,
  register, revoke and introspect endpoints are skipped, plus, on the routes of a resource (see the next
  point), requests that carry no cookie or other credential a browser sends by itself (CSRF has nothing to
  protect there, and an expired or revoked token gets the authenticator's 401) and requests with a cookie and a
  bearer token that validates. A request with a cookie and a token of this server's prefix that does not
  validate gets the normal CSRF check, and so does the login page. The forms are built with `FormHelper`; a
  template override must do the same ([pages](pages.md#forms-and-csrf)). The core also signs the forms with
  `OAuthServer.secret`.
- **A token works only on the routes of its resource.** The Token authenticator authenticates a token only
  when both the request path and the static part of the template of the route that matched it are below
  the path of the resource it was issued for (`/api` for `https://example.com/api`, or its `paths` option);
  anywhere else a request carrying this server's token is refused with 401, and `OAuthServer::csrfSkip()`
  skips CSRF on a resource's routes only by the same rule. A consented token therefore cannot act as the person
  on a session page whose route is not connected below the resource's path, including routes that start with
  a placeholder (`/{tenant}/...`). What you connect below that path is part of the resource, and inside it
  your actions still check scopes ([protecting-apis](protecting-apis.md#where-a-token-works)).
- **A bearer token is never a browser login.** The consent and connections pages accept a session login
  only. Stateless authenticators (Token, HttpBasic, JWT, ...) and impersonation are refused, so a token
  cannot approve a client or mint tokens.
- **The Token authenticator is stateless and only challenges its own tokens.** Nothing it authenticates
  is persisted in a session, and it never answers 401 for other schemes ([protecting-apis](protecting-apis.md)).
- **The authorization check is skipped only for the plugin's own endpoints.** `OAuthController` calls
  `skipAuthorization()` on `cakephp/authorization` for its requests and never for any other controller.
- **Pages keep the core's hardening headers** (`no-store`, `X-Frame-Options: DENY`, a restrictive
  Content-Security-Policy, `Referrer-Policy: no-referrer`). With an application layout, the policy is
  extended for same-origin styles, images and fonts only, never for scripts or framing
  ([pages](pages.md#content-security-policy)).
- **Subjects are matched exactly.** `OrmUserProvider` compares the key as a string and refuses a different
  spelling of the same number; the tables use `utf8mb4_bin` on MySQL and MariaDB.
- **Inactive people stop at once.** The person is loaded again with your finder on every use.
- **The pages never headline a client by a name it chose.** The consent page names a metadata document client
  by its `client_id` host and a dynamically registered client by the host its answer goes to ("An application on
  this computer" for a private-use scheme); the declared name appears only inside a `<q>` element on an
  unverified line, so it cannot pose as the server's text. The connections page labels a dynamically registered
  client by the hosts of its redirect URIs. The shipped templates do this; keep it in overrides
  ([pages](pages.md#variables)).
- **No redirect before the login, and none to a client nobody vouched for.** The core sends an error back to the
  client only after the person signed in, and only when an administrator registered the client or this person
  approved it before. Otherwise the error page names the destination and offers a plain link
  (`CakeErrorPageRenderer` implements the core's `RedirectNoticeRendererInterface`;
  [pages](pages.md#the-error-page-and-untrusted-clients)).
- **A remembered consent does not answer for a client whose identity cannot be confirmed.** A public client
  with a loopback or private-scheme redirect (any program on the computer can receive the answer) sees the
  consent page on every connection, with a line saying the person approved it before.
- **Never logging tokens.** The plugin's own code does not write token values, client secrets or codes to
  any log or event. Its parameters that carry them (the configuration with `secret` and
  `registration.initialAccessToken`, the test trait's bearer token) are `#[\SensitiveParameter]`, like the
  core's, so a stack trace in a log shows `Object(SensitiveParameterValue)` instead. Frames of other libraries
  are outside this (the core's
  [secrets in logs and traces](https://github.com/CakeDC/oauth-server/blob/1.x/docs/security.md#secrets-in-logs-and-traces)
  names them), and so is your own code: keep `zend.exception_ignore_args = On` in production (the default of
  PHP's production `php.ini`), which drops every argument from traces.
- **A derived secret needs a real salt.** Without `OAuthServer.secret`, the secret is derived from
  `Security.salt`, which must be at least 32 characters.

## Logging

The plugin logs with the scope `oauth`. When no log engine receives that scope (the skeleton's `debug`
and `error` engines have no scopes, so they do not), the plugin registers a `FileLog` named `oauth` that
writes `logs/oauth.log`. `bin/cake oauth check` reports `Logging` and warns when security events would
not be recorded. To send them elsewhere, configure your own engine for the scope:

```php
'Log' => [
    'oauth' => [
        'className' => 'Cake\Log\Engine\FileLog',
        'path' => LOGS,
        'file' => 'oauth',
        'scopes' => ['oauth'],
    ],
],
```

Events (the audit trail) are described in [events](events.md).

## What only you can do

- **Cut a person off.** Deactivating the account is enough (tokens stop validating). In every other case
  run `bin/cake oauth token revoke --subject ID --consents`, so tokens and remembered consents go.
- **Revoke after policy changes.** `canAuthorize()` runs at `/authorize` only. Revoke tokens when the rule
  changes ([users](users.md#cutting-a-person-off)).
- **Introspection is a privilege.** `allowIntrospection` lets a client learn about any token of its
  resource; grant it only to resource servers you trust.
- **Check scopes on your routes.** Without `users.resource` the authenticator accepts default-resource
  tokens on the routes below the default resource's path; check `OAuthServer::token($request)->hasScope()`
  where it matters. Keep session pages out of your resources' paths. Think twice before setting `paths` or
  `tokenPaths` to `['/']`: it makes tokens work on every route.
- **Do not run the endpoints inside a request-wide transaction** ([deployment](deployment.md#database)).
- **Listeners must not throw** ([events](events.md#rules-for-listeners)).

## Production checklist

- [ ] `bin/cake oauth check` has no `FAIL`, and you read every `WARN`.
- [ ] `OAuthServer.issuer` (or `App.fullBaseUrl`) is set explicitly to the public https URL, never left to
      CakePHP's `Host` header fallback ([deployment](deployment.md#https-and-the-issuer)); subdirectory installs
      have the well-known rewrite ([deployment](deployment.md#applications-in-a-subdirectory)).
- [ ] `OAuthServer.secret` is set from the environment (at least 32 random characters), not derived, and
      not in version control.
- [ ] `rateLimit.cache` names a cache shared by all PHP processes. It is not `null`.
- [ ] `trustProxy` is enabled only when the application is firewalled so that only your proxies reach it
      (Cake does not check `REMOTE_ADDR` against the list), with the proxies listed
      ([deployment](deployment.md#trusted-proxies-and-the-client-ip)).
- [ ] `OAuthServer::csrfSkip()` is in your `CsrfProtectionMiddleware`.
- [ ] `bin/cake oauth prune` runs daily.
- [ ] Registration is `closed` or `token` unless you need `open`; `cimd.allowedHosts` lists the hosts you
      expect (include `claude.ai` if you use it).
- [ ] Features you do not use are off: `introspection`, `clientCredentials`, `personalTokens`.
- [ ] `tokenPrefix` names your product.
- [ ] Anthropic's egress range `160.79.104.0/21` is not blocked or challenged on the OAuth and MCP paths (it stays subject to the rate limits).
- [ ] A listener records `OAuthServer.refreshTokenReused` and `OAuthServer.tokenRevoked`.
- [ ] Revocation is wired to the events that matter to you: password change, account removal, role change.
- [ ] Backups of the `oauth_*` tables are encrypted. (`OrmStorage` runs on the connection of the plugin's tables
      and the people table is read through your own table, usually the `default` connection, so the database
      user of the application needs both; only a separate connection for the OAuth tables could narrow it.)
- [ ] `bin/cake oauth check` has no warning about query logging leaking tokens: with cakedc/users, the
      one-time login authenticator is the plugin's ([cakedc-users](cakedc-users.md#one-time-login-links)).
