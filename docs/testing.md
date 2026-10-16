# Testing

`CakeDC\OAuthServer\TestSuite\OAuthTestTrait` lets integration tests call your protected routes as an
authenticated OAuth client, without walking through the OAuth flow. Use it together with CakePHP's
`IntegrationTestTrait`.

```php
// tests/TestCase/Controller/Api/PostsControllerTest.php
namespace App\Test\TestCase\Controller\Api;

use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\TestSuite\OAuthTestTrait;

class PostsControllerTest extends TestCase
{
    use IntegrationTestTrait;
    use OAuthTestTrait;

    protected array $fixtures = ['app.Users'];

    protected function setUp(): void
    {
        parent::setUp();
        OAuthServer::reset();
    }

    public function testEditorCanReadPosts(): void
    {
        $this->actAsOAuth(1, ['content:read'], 'https://example.com/mcp');
        $this->get('/api/posts');

        $this->assertResponseOk();
    }

    public function testNoTokenIsAnonymous(): void
    {
        // What an anonymous request gets depends on your authentication setup.
        $this->get('/api/posts');

        $this->assertResponseCode(401);
    }
}
```

## The methods

| Method | Does |
| --- | --- |
| `oauthTokenFor($identity, array $scopes = [], ?string $resource = null): string` | Issues a token and returns its value |
| `withOAuthToken(string $token): void` | Sends the token as `Authorization: Bearer ...` on the next request |
| `actAsOAuth($identity, array $scopes = [], ?string $resource = null): string` | Both of the above; returns the token |

- `$identity` is the person: an id, an `Authentication\IdentityInterface`, an entity or an array with `id`.
  The person must be known to the configured user provider (the `finder` must find them), or
  `InvalidArgumentException` is thrown.
- `$scopes` empty means the resource's `defaultScopes`. Scopes the resource does not declare, or the person
  may not hold (`userProvider.scopes`), throw `InvalidArgumentException`.
- `$resource` is a resource identifier; `null` is the default resource. An undeclared one throws
  `InvalidArgumentException`.

## What to know

- The token is a personal token built through the public connection service, valid for one day. That
  means `OAuthServer.personalTokens` must be `true` in the test configuration; with `false` the trait
  throws `LogicException` with a clear message.
- The header applies to the **next request only**: IntegrationTestTrait clears request headers after
  sending. Call `withOAuthToken()` or `actAsOAuth()` again before each request. A second call replaces the
  token instead of sending two `Authorization` values.
- The configuration is read when a token is issued, but the application under test builds its server from
  `OAuthServer::server()`, which is cached. Call `OAuthServer::reset()` after changing the `OAuthServer`
  configuration inside a test (and in `setUp()` as shown).
- The authenticator that the route uses must be loaded in your `getAuthenticationService()`, for the same
  resource you pass here. See [protecting-apis](protecting-apis.md).
- Tests do not need a rate limit cache: set `'rateLimit' => ['cache' => null]` in the test configuration,
  as the plugin's own tests do. Counters would otherwise accumulate across tests in one process.
- For code that needs a fixed time or a fake metadata fetch, `OAuthServer.services` takes `clock`,
  `transport` and `dns` replacements; see [configuration](configuration.md#services).
