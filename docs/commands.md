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
Warning: Store the secret now; it is not shown again.
```

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
[PASS] Login URL: /users/login
[PASS] CSRF: the token, register, revoke and introspect endpoints are skipped
[PASS] RBAC: cakedc/users is not loaded
[PASS] Rate limiting: cache "default"
[PASS] Client metadata documents: enabled
[WARN] Logging: no log engine handles the "oauth" scope, so security events are not recorded
```

| Check | Fails or warns when |
| --- | --- |
| Secret | `OAuthServer.secret` is shorter than 32 characters (fail), or is not set and `Security.salt` is missing or short (fail); a derived secret only warns |
| Configuration | The configuration is invalid (an unknown key, a bad type, an undeclared resource, a `tokenPrefix` that is not 1 to 16 lowercase letters or digits) |
| Issuer | The issuer is invalid (fail). Warns for plain http, for an issuer with a path (the RFC 8414 document must be served at the host root), and when the issuer path differs from `App.base` |
| Tables | A table is missing or `oauth_tokens` has no `family_started_at` (migrate; see [installation](installation.md#migrations)), or on MySQL and MariaDB a column is not `utf8mb4_bin` |
| Users | The users table has no configured finder. A custom provider is reported as `custom user provider` |
| Users integration | Only with `CakeDC/Users`: `OAuthServer.users` is invalid (fail); otherwise prints what the integration's Token authenticator validates and where |
| Login URL | Prints the resolved login URL; fails when it cannot be built |
| CSRF | The `CsrfProtectionMiddleware` of your application does not skip the token endpoint (fail). Warns when it cannot inspect the middleware |
| RBAC | Only with `CakeDC/Users`: RBAC denies the OAuth endpoints (fail). See [cakedc-users](cakedc-users.md#what-oauth-check-says) |
| Rate limiting | `rateLimit.cache` is `null` (warn: the token endpoints are not throttled), or the named cache configuration does not exist (fail) |
| Client metadata documents | Metadata documents are enabled but `ext-curl` is missing (fail), or `rateLimit.cache` is `null` so there is no fetch budget and no negative cache (warn) |
| Logging | No log engine receives the `oauth` scope (warn) |

On the command line an invalid issuer does not break `bin/cake`: the routes fall back to `/oauth` and the
metadata route is skipped, so `oauth check` can report the problem. The same holds for an invalid
`OAuthServer.users` setting with `CakeDC/Users`: the integration step is skipped on the command line.
Web requests fail at boot instead.
That also means a test of your application run on the CLI does not fail on a bad issuer.
