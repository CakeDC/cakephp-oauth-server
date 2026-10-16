# CakeDC OAuth Server for CakePHP

Plugin name `CakeDC/OAuthServer`, package `cakedc/cakephp-oauth-server`. It runs on top of the core
library `cakedc/oauth-server`, whose documentation covers the OAuth side in depth:

- [Concepts](https://github.com/CakeDC/oauth-server/blob/1.x/docs/concepts.md)
- [Endpoints](https://github.com/CakeDC/oauth-server/blob/1.x/docs/endpoints.md)
- [Security model](https://github.com/CakeDC/oauth-server/blob/1.x/docs/security.md)
- [Clients, including claude.ai and Claude Code](https://github.com/CakeDC/oauth-server/blob/1.x/docs/clients.md)
- [Operations](https://github.com/CakeDC/oauth-server/blob/1.x/docs/operations.md)

## This plugin's pages

| Page | What you learn |
| --- | --- |
| [installation](installation.md) | Install, load, migrate, CSRF, routes, authentication |
| [configuration](configuration.md) | Every `OAuthServer` key, type and default |
| [users](users.md) | `OrmUserProvider`, callbacks, custom providers, the sign-in context |
| [cakedc-users](cakedc-users.md) | What happens automatically with `CakeDC/Users`, and the manual snippets |
| [protecting-apis](protecting-apis.md) | The `CakeDC/OAuthServer.Token` authenticator and scope checks |
| [pages](pages.md) | Overriding templates and layouts, translations |
| [commands](commands.md) | `oauth client add`, `oauth check` and the rest |
| [events](events.md) | `OAuthServer.*` events |
| [testing](testing.md) | `OAuthTestTrait` for integration tests |
| [mcp](mcp.md) | Protecting a MCP server |
| [deployment](deployment.md) | https, proxies, subdirectory installs, nginx, caches |
| [security](security.md) | What the plugin adds, production checklist |
| [troubleshooting](troubleshooting.md) | Symptoms and fixes |

## How the pieces fit

- `OAuthServerPlugin` connects the routes, registers the commands and, when `CakeDC/Users` is loaded,
  wires the authenticator and the RBAC rule.
- `OAuthController` hands each request to the core's handler. The core renders the pages through Cake
  views of this plugin.
- `OrmStorage` keeps clients, codes, tokens and consents in four tables (`oauth_clients`,
  `oauth_authorization_codes`, `oauth_tokens`, `oauth_consents`) through the Cake ORM.
- `OAuthServer` is the static entry point: `OAuthServer::server()`, `OAuthServer::forRequest()`,
  `OAuthServer::reset()`, `OAuthServer::csrfSkip()`, `OAuthServer::pageCsp()`, `OAuthServer::token()` and
  `OAuthServer::rbacPermissions()`.

## Public API

Before 1.0 the supported surface is: `OAuthServerPlugin`, `OAuthServer` (except `pageCsp()` and
`forRequest()`, which the plugin's controller uses), `TokenAuthenticator` (except `resolve()`, which
`oauth check` uses) and `OAuthServerTokenAuthenticator`, `OAuthIdentity`, `OrmStorage`, `OrmUserProvider`,
`SessionUserContext`, `QuotedName` (prints a client-chosen name in template overrides,
[pages](pages.md#variables)), the Table and Entity classes (no entity field is mass assignable and the hashes are hidden;
pass `accessibleFields` when you patch one), the commands and `OAuthTestTrait`, plus the configuration keys and
events documented here. Everything else (`PluginConfig`, `ServerFactory`, the `Cake*Renderer` classes and
`CakeTemplateRenderer`, `UsersIntegration`, `UsersOneTimeTokenAuthenticator`, `PluginMessagesLoader`,
`UtcDateTimeType`, `RbacPermissionsProvider`, the event dispatcher and the logger) is marked `@internal` and may
change in any release. `RbacPermissionsProvider` and `CakeDC/OAuthServer.UsersOneTimeToken` stay referenced by
name in the cakedc/users configuration; those values are configuration, the classes themselves are not API.
