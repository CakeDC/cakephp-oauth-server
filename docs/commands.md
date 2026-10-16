# Commands

The plugin registers six commands, all run with `bin/cake` (inside DDEV: `ddev exec bin/cake ...`). The
commands use the same configuration and storage as the web endpoints.

| Command | Purpose |
| --- | --- |
| `oauth client add` | Register a client by hand |
| `oauth client list` | List the clients |
| `oauth client revoke` | Revoke a client and its tokens |
| `oauth token revoke` | Revoke the tokens of a person or a client |
| `oauth prune` | Delete expired data |
| `oauth check` | Check the setup |

## oauth client add

```bash
bin/cake oauth client add NAME [--redirect-uri URI]... [--confidential] [--grant GRANT]...
    [--scope SCOPE]... [--introspection] [--native]
```

Registers a client (type `Registered`). `NAME` is the display name.

| Option | Meaning |
| --- | --- |
| `--redirect-uri` | A redirect URI. Repeat for more |
| `--confidential` | Give the client a secret (HTTP Basic authentication at the token endpoint) |
| `--grant` | `authorization_code`, `refresh_token` or `client_credentials`. Repeat for more. Default: the first two |
| `--scope` | A scope the client may ever get. Repeat for more. Default: any scope the resources declare |
| `--introspection` | Allow the client to call `/introspect`. Confidential clients only; a trusted resource server privilege |
| `--native` | The client is a native application (loopback or private-scheme redirect URIs) |

Examples:

```bash
# A web application with a secret
bin/cake oauth client add "Reporting dashboard" --confidential \
    --redirect-uri https://dashboard.example.com/oauth/callback

# A service acting for itself (also needs userProvider.forClient, see users.md)
bin/cake oauth client add "Nightly import" --confidential --grant client_credentials --scope content:read
```

Output:

```
client_id: 0b6f0a3c...
client_secret: (the secret, shown once)
Store the secret now; it is not shown again.
```

The last line is a warning and goes to standard error, so `bin/cake oauth client add ... > client.txt` keeps only
the id and the secret in the file.

The secret appears only for confidential clients, once. A refused input (for example a public client with
client credentials) prints the error and exits with a non-zero code. The service identity for the client
credentials grant is described in [users](users.md#forclient).

## oauth client list

```bash
bin/cake oauth client list
```

Prints a table of every client: client id, name, type, authentication method, created, last used and
revoked (`-` when empty). Clients created from metadata documents (`MetadataDocument`) and by dynamic
registration (`Dynamic`) are listed next to the ones you added.

```
Client id   Name                  Type         Authentication       Created           Last used         Revoked
0b6f0a3c... Reporting dashboard   registered   client_secret_basic  2026-10-16 12:00  2026-10-16 12:30  -
```

(The real output is drawn as a table with borders.)

## oauth client revoke

```bash
bin/cake oauth client revoke CLIENT_ID
```

Marks the client revoked, forever, and revokes every token it holds:

```
Revoked the client and 3 token(s).
```

An unknown id prints `No client with that id.` and exits with a non-zero code.

## oauth token revoke

```bash
bin/cake oauth token revoke --subject ID [--consents]
bin/cake oauth token revoke --client CLIENT_ID
```

| Option | Meaning |
| --- | --- |
| `--subject` | The person's id (the primary key of the users table). Revokes their access, refresh and personal tokens |
| `--consents` | With `--subject`: also delete the person's remembered consents, so no client they approved before can skip the consent page |
| `--client` | The client id. Revokes every token of that client (the client itself stays valid; use `oauth client revoke` to end it) |

```
Revoked 4 token(s).
Deleted 2 consent(s).
```

The `Deleted ... consent(s)` line appears with `--consents`. Pass either `--subject` (optionally with
`--consents`) or `--client`; any other combination prints
`Pass either --subject (optionally with --consents) or --client.` and fails.

To cut a person off completely, use `--subject ID --consents`.

## oauth prune

```bash
bin/cake oauth prune
```

Deletes what is no longer needed: expired authorization codes, expired and revoked tokens (kept for
`retentionDays` first) and clients nobody needs any more. Revoked clients stay as records, because revocation
is permanent. It prints:

```
Deleted 12 codes, 340 tokens and 1 clients.
```

Run it daily:

```
# crontab -e (as the user that runs the application)
17 3 * * * cd /var/www/app && bin/cake oauth prune >> logs/oauth_prune.log 2>&1
```

Pruning does not weaken the family lifetime cap: it is stored with every token (`family_started_at`).
More in the core's [operations](https://github.com/CakeDC/oauth-server/blob/1.x/docs/operations.md).

## oauth check

```bash
bin/cake oauth check
```

Runs the checks below and prints one line each, `[PASS]`, `[WARN]` or `[FAIL]`. The exit code is non-zero
when any check fails, so it is suitable for a deployment pipeline.

```
[WARN] Secret: derived from Security.salt; set OAuthServer.secret to rotate it without changing the salt
[PASS] Configuration: 1 resource(s), endpoints under https://example.com/oauth
[PASS] Issuer: https://example.com
[PASS] Tables: all four tables exist
[PASS] Users: Users with finder "active"
[PASS] Users integration: cakedc/users is not loaded
[PASS] Login URL: /users/login
[PASS] Routes: /oauth/token reaches the plugin
[PASS] Middleware: RoutingMiddleware runs before the CSRF and authentication middleware
[PASS] CSRF: the token, register, revoke and introspect endpoints are skipped
[PASS] Authenticators: Token comes before Session
[PASS] RBAC: cakedc/users is not loaded
[PASS] Rate limiting: cache "default"
[PASS] Client metadata documents: enabled
[PASS] Logging: the "oauth" log engine is configured
```

| Check | Fails or warns when |
| --- | --- |
| Secret | `OAuthServer.secret` is shorter than 32 characters (fail), or is not set and `Security.salt` is missing or short (fail); a derived secret only warns |
| Configuration | The configuration is invalid (an unknown key, a bad type, an undeclared resource, a `tokenPrefix` that is not 1 to 16 lowercase letters or digits) |
| Issuer | The issuer is invalid (fail). Warns for plain http, for an issuer with a path (the RFC 8414 document must be served at the host root), and when the issuer path differs from a configured `App.base`. When `App.base` is `false` (Cake detects the directory per request) the CLI cannot compare them and says so instead of guessing |
| Tables | Inspects the connection of the plugin's tables (not necessarily `default`; the message names it). Fails when a table is missing, a column of the current migrations is missing (such as `oauth_tokens.family_started_at`) or a unique key is missing (`client_id_hash`, `code_hash`, `token_hash`, and subject, client and resource of a consent): migrate, see [installation](installation.md#migrations). On MySQL and MariaDB it also fails when a column is not `utf8mb4_bin` |
| Users | The users table has no configured finder. A custom provider is reported as `custom user provider` |
| Users integration | Only with `CakeDC/Users`: `OAuthServer.users` is invalid, or the integration's resource is at the host root with neither `OAuthServer.users.paths` nor `OAuthServer.tokenPaths` set (fail: the authenticator refuses every token); otherwise prints what the integration's Token authenticator validates and where. Warns when the one-time login authenticator (`Auth.Authenticators.OneTimeToken`) is not the plugin's guarded one, so it would read the `token` sent to the revoke and introspect endpoints ([cakedc-users](cakedc-users.md#one-time-login-links)) |
| Login URL | Prints the resolved login URL; fails when it cannot be built. Warns when a local string URL matches no route or controller (another site's URL is not checked) |
| Routes | `<prefix>/token` does not reach the plugin's controller: no route, or a route of your application connected before the plugin's takes it (fail) |
| Middleware | Your middleware queue, plus what your plugins add, has `CsrfProtectionMiddleware` (or the session one) or `AuthenticationMiddleware` before `RoutingMiddleware` (warn): there is no matched route yet, so a bearer request is never skipped by `csrfSkip()` and the Token authenticator refuses every token. Also warns when there is no `RoutingMiddleware` |
| CSRF | The `CsrfProtectionMiddleware` or `SessionCsrfProtectionMiddleware` of your application does not skip the token endpoint (fail), or also skips a session route: it probes `<prefix>/authorize`, `<prefix>/connections`, `/` and your login (fail; a callback like `fn () => true`). Warns when there is no CSRF middleware in the queue (the consent and connections pages rely on it) or when it cannot inspect the middleware |
| Authenticators | Builds your authentication service with probe requests at your bearer paths. Warns when the Session authenticator comes before the Token authenticator, or when there is no Token authenticator (ignore that one when your resources live in another application). Fails when the service cannot be built, or when a Token authenticator would refuse every token: an undeclared `resource`, a resource at the host root without `paths`, an invalid `paths`. With cakedc/users it reads `Auth.Authenticators` |
| RBAC | Only with `CakeDC/Users`: RBAC denies the OAuth endpoints (fail). See [cakedc-users](cakedc-users.md#what-oauth-check-says) |
| Rate limiting | `rateLimit.cache` is `null` (warn: the token endpoints are not throttled), the named cache configuration does not exist (fail), or it uses the `Array` or `Null` engine, which keeps nothing from one request to the next (warn: nothing is throttled) |
| Client metadata documents | Metadata documents are enabled but `ext-curl` is missing (fail), or `rateLimit.cache` is `null` or an `Array` or `Null` engine, so there is no fetch budget and no negative cache (warn) |
| Logging | No log engine receives the `oauth` scope (warn) |

No configuration breaks `bin/cake`: with an invalid one the routes are still connected (see
[configuration](configuration.md#an-invalid-configuration)), commands and migrations run, and `oauth check`
reports the problem on its `Configuration` line (or the line of the check that hit it). The web behaves the same
way: the application keeps working and only the OAuth endpoints answer 503. So a test of your application does
not fail on a bad `OAuthServer` setting unless it calls an OAuth endpoint; run `oauth check` in your pipeline.
