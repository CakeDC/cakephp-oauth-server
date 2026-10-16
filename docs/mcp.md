# Protecting an MCP server

The Model Context Protocol (MCP) uses OAuth 2.1 for its HTTP authorization. Your MCP endpoint is the
resource server and this plugin is the authorization server. The core's [mcp](https://github.com/CakeDC/oauth-server/blob/1.x/docs/mcp.md)
page has the complete picture, with a full example for the official MCP PHP SDK (`mcp/sdk`); this page
shows how the pieces map to CakePHP.

`cakedc/cakephp-mcp` is the CakePHP plugin for building MCP servers. Its `oauth` mode, which wires this
plugin in for you, is planned for `cakedc/cakephp-mcp` 2.1. Until then, connect them by hand as below.

## 1. Declare the endpoint as a resource

The resource identifier is the public URL of your MCP endpoint, and it must be the same string in the
configuration, in your protected resource metadata and in the URL clients type:

```php
// config/app_local.php
'OAuthServer' => [
    'resources' => [
        'https://example.com/mcp' => [
            'name' => 'Example MCP',
            'scopes' => [
                'content:read' => 'Read your posts',
                'content:write' => 'Edit drafts',
                'content:publish' => 'Publish posts',
            ],
            'implies' => [
                'content:publish' => ['content:write'],
                'content:write' => ['content:read'],
            ],
            'defaultScopes' => ['content:read'],
        ],
    ],
],
```

## Which scopes to declare

Think in levels of access rather than in tools: one scope to read, one to change, one for actions that
cannot be undone (publish, delete, send). Use `implies` so a higher level includes the lower ones, and
`defaultScopes` for the safest level. Each scope's description is what the person reads on the consent
page, so write it as a sentence about their data ("Read your posts"). Check scopes per tool with the SDK's
`ScopePolicy` (see the core page). Give people only the scopes they may hold with the `scopes` callback
([users](users.md#scopes)).

## 2. Give the SDK's middleware a validator

```bash
composer require mcp/sdk nyholm/psr7
```

```php
use CakeDC\OAuthServer\OAuthServer;
use Mcp\Server\Transport\Http\Middleware\AuthorizationMiddleware;

$validator = OAuthServer::server()->mcpTokenValidator('https://example.com/mcp');

$middleware = new AuthorizationMiddleware($validator, $metadata, $policy, $responseFactory, $streamFactory);
```

`mcpTokenValidator()` throws `InvalidArgumentException` when the resource is not declared and
`LogicException` when `mcp/sdk` is missing. `$metadata` (`ProtectedResourceMetadata`), `$policy`
(`ScopePolicy`) and the other middleware of the transport are built as in the core's example. The SDK is
under development, so check its documentation for the exact transport calls.

The OAuth endpoints themselves (`/oauth/authorize`, `/oauth/token`, the metadata and so on) are routed by
this plugin, next to your MCP endpoint.

MCP clients POST to your endpoint with `Authorization: Bearer ...`. With `OAuthServer::csrfSkip()` in your
`CsrfProtectionMiddleware` (see [installation](installation.md#csrf)) those POSTs are not rejected with 403,
while CSRF stays on for session routes. The skip applies below the path of your MCP resource only
(`/mcp` for `https://example.com/mcp`), and the Token authenticator likewise accepts the token only there,
so the token cannot be used on the rest of your application. Never disable CSRF globally.

## 3. Connect a client

Connecting claude.ai and Claude Code is described in the core's
[clients](https://github.com/CakeDC/oauth-server/blob/1.x/docs/clients.md): nothing needs registering
because they use Client ID Metadata Documents. Your MCP endpoint and the metadata must be reachable from the
internet over https, and you must not block or challenge Anthropic's egress range `160.79.104.0/21` on
the OAuth and MCP paths (see [deployment](deployment.md#claudes-egress-range)). The range is still subject to
the plugin's rate limits.

If you set `cimd.allowedHosts`, include `claude.ai`. With `cimd.enabled` set to `false`, claude.ai needs
`registration.mode` `open` or a client you registered with `bin/cake oauth client add`.

Run `bin/cake oauth check` before you try.
