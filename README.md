# CakeDC OAuth Server for CakePHP

An OAuth 2.1 authorization server for CakePHP 5 applications. It lets AI assistants (claude.ai, Claude
Code, other MCP clients) and your own programs get access tokens for your application's people. People
sign in with the login your application already has, approve what a client may do on a consent page, and
review or revoke their connections on a connections page.

The plugin is a thin CakePHP layer on top of [cakedc/oauth-server](https://github.com/CakeDC/oauth-server),
the framework independent core. The core does the OAuth work (endpoints, PKCE, refresh token rotation,
Client ID Metadata Documents, dynamic registration, rate limits). The plugin adds what a Cake application
needs: ORM storage and a migration, routes, an authenticator for `cakephp/authentication`, Cake views for
the pages, console commands, events on Cake's event manager and a test trait. The OAuth concepts, the
endpoint reference, the security model and the client setup guides live in the core's documentation, and
this documentation links to them instead of repeating them.

## Requirements

- PHP 8.2 or later
- CakePHP 5.0 or later
- `cakephp/authentication` 3.x (your application needs a login that sets the `identity` request attribute)
- `cakephp/migrations` 4 or 5
- Optional: `cakedc/users` for a ready-made login (see [cakedc-users](docs/cakedc-users.md)), `cakedc/auth`
  for RBAC rules, `cakephp/authorization`

## Five minute start

1. Install the plugin.

   ```bash
   composer require cakedc/cakephp-oauth-server
   ```

2. Load it in `src/Application.php`.

   ```php
   public function bootstrap(): void
   {
       parent::bootstrap();
       $this->addPlugin('CakeDC/OAuthServer');
   }
   ```

3. Create the tables.

   ```bash
   bin/cake migrations migrate -p CakeDC/OAuthServer
   ```

4. Declare the resource you protect, in `config/app_local.php` (one resource is enough to start). The issuer
   defaults to `App.fullBaseUrl` and the secret is derived from `Security.salt`.

   ```php
   return [
       'OAuthServer' => [
           'resources' => [
               'https://example.com/mcp' => [
                   'name' => 'Example MCP',
                   'scopes' => [
                       'content:read' => 'Read your posts',
                       'content:write' => 'Edit drafts',
                   ],
                   'implies' => ['content:write' => ['content:read']],
                   'defaultScopes' => ['content:read'],
               ],
           ],
       ],
   ];
   ```

5. Let OAuth clients call the token endpoints, and bearer authenticated requests below your resources' paths, without a CSRF token. In `Application::middleware()`:

   ```php
   use CakeDC\OAuthServer\OAuthServer;
   use Cake\Http\Middleware\CsrfProtectionMiddleware;
   use Psr\Http\Message\ServerRequestInterface;

   $csrf = new CsrfProtectionMiddleware();
   $csrf->skipCheckCallback(fn (ServerRequestInterface $request): bool => OAuthServer::csrfSkip($request));
   $middlewareQueue->add($csrf);
   ```

6. Check the setup.

   ```bash
   bin/cake oauth check
   ```

   No line may say `FAIL`. A `WARN` is a hint (for example, that the secret is derived from `Security.salt`).

7. Connect a client. The metadata document is at `https://example.com/.well-known/oauth-authorization-server`.
   To connect Claude, follow [clients](https://github.com/CakeDC/oauth-server/blob/1.x/docs/clients.md) in
   the core documentation. Protect your MCP endpoint or API as described in
   [protecting-apis](docs/protecting-apis.md) and [mcp](docs/mcp.md).

The consent page needs a person who is signed in. If your application has no login yet, read
[installation](docs/installation.md#authentication) first.

## Documentation

- [Contents](docs/index.md)
- [Installation](docs/installation.md): Composer, loading, migrations, CSRF, routes, authentication
- [Configuration](docs/configuration.md): every key, with defaults
- [Users](docs/users.md): who may sign in, who may authorize, service identities
- [cakedc/users](docs/cakedc-users.md): the plug and play integration
- [Protecting APIs](docs/protecting-apis.md): the token authenticator and scope checks
- [Pages](docs/pages.md): consent and connections pages, layouts, templates, translations
- [Commands](docs/commands.md): the `oauth` console commands
- [Events](docs/events.md): the six events and an audit log listener
- [Testing](docs/testing.md): `OAuthTestTrait`
- [MCP](docs/mcp.md): protecting a `cakedc/cakephp-mcp` server
- [Deployment](docs/deployment.md): https, proxies, subdirectories, nginx
- [Security](docs/security.md): what the plugin adds and a production checklist
- [Troubleshooting](docs/troubleshooting.md)

Not a CakePHP application? Use the core package [cakedc/oauth-server](https://github.com/CakeDC/oauth-server)
directly.

## License

MIT. See [LICENSE](LICENSE).
