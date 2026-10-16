# Changelog

## 1.0.0-beta1 (unreleased)

First release. An OAuth 2.1 authorization server for CakePHP 5 on top of cakedc/oauth-server.

- `OAuthServer::csrfSkip()` skips CSRF for the client endpoints and for requests with a bearer token of this
  server below the path of a resource (`OAuthServer.tokenPaths` or the `$paths` argument override it).
- The Token authenticator has a `paths` option (default: the path of its resource) and refuses, with 401, a
  request that carries this server's token anywhere else, so a token for one resource cannot act as the
  person on the rest of the application.
- People tables keyed by a column other than `id` work: the identity reports the key as its identifier.
- An invalid `OAuthServer.users` setting no longer breaks `bin/cake` with cakedc/users; `oauth check` reports it.
- `oauth check` also warns about a missing CSRF middleware and a Session authenticator before the Token one,
  checks that a string login URL routes, and no longer accuses subdirectory installs of an `App.base` mismatch
  when the base is detected at runtime.
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
