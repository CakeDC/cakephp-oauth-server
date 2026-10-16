<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\View;

use Cake\Http\ServerRequest;
use Cake\I18n\I18n;
use Cake\I18n\Package;
use Cake\Routing\Router;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Client\ApplicationType;
use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientAuthMethod;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuth\Server\Connections\Connection;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\Owner\ResourceOwner;
use CakeDC\OAuth\Server\Owner\SubjectType;
use CakeDC\OAuth\Server\Resource\ProtectedResource;
use CakeDC\OAuth\Server\Token\Token;
use CakeDC\OAuth\Server\Token\TokenType;
use CakeDC\OAuth\Server\View\ConnectionsView;
use CakeDC\OAuth\Server\View\ConsentView;
use CakeDC\OAuthServer\Test\Support\Html;
use CakeDC\OAuthServer\View\CakeConnectionsRenderer;
use CakeDC\OAuthServer\View\CakeConsentRenderer;
use CakeDC\OAuthServer\View\CakeErrorPageRenderer;
use DateTimeImmutable;

class RenderersTest extends TestCase
{
    private const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';

    /**
     * @param \CakeDC\OAuth\Server\Client\ClientType $type Type.
     * @param string $clientId The client_id.
     * @param string $name Self-asserted name.
     * @param array<string> $redirects Redirect URIs.
     * @return \CakeDC\OAuth\Server\Client\Client
     */
    private function client(
        ClientType $type = ClientType::Dynamic,
        string $clientId = 'abc',
        string $name = 'Claude <AI>',
        array $redirects = [self::CALLBACK],
    ): Client {
        return new Client(
            'id',
            $clientId,
            $type,
            ApplicationType::Web,
            $name,
            $redirects,
            ['authorization_code'],
            ClientAuthMethod::None,
            new DateTimeImmutable(),
        );
    }

    /**
     * @return \CakeDC\OAuth\Server\Resource\ProtectedResource
     */
    private function resource(): ProtectedResource
    {
        return new ProtectedResource('http://localhost/mcp', 'Test MCP', ['content:read' => 'Read your posts']);
    }

    /**
     * @param \CakeDC\OAuth\Server\Client\Client|null $client Client.
     * @param bool $offline Whether a refresh token is issued.
     * @param string $action The form action.
     * @param \Cake\Http\ServerRequest|null $request The request.
     * @return string
     */
    private function consent(
        ?Client $client = null,
        bool $offline = true,
        string $action = '/oauth/authorize',
        ?ServerRequest $request = null,
    ): string {
        $request ??= (new ServerRequest())->withAttribute('csrfToken', 'csrf-value');

        return (new CakeConsentRenderer($request, null))->render(new ConsentView(
            $client ?? $this->client(),
            new ResourceOwner('1', 'Ada'),
            $this->resource(),
            ['content:read' => 'Read your posts'],
            $offline,
            self::CALLBACK,
            $action,
            ['client_id' => 'abc', 'consent_token' => 't'],
        ));
    }

    /**
     * @param array<\CakeDC\OAuth\Server\Connections\Connection> $connections Connections.
     * @param array<\CakeDC\OAuth\Server\Token\Token> $tokens Personal tokens.
     * @param array<string, mixed> $creatable Creatable resources.
     * @param bool $enabled Personal tokens feature.
     * @param \Cake\Http\ServerRequest|null $request The request.
     * @return string
     */
    private function connections(
        array $connections = [],
        array $tokens = [],
        ?array $creatable = null,
        bool $enabled = true,
        ?ServerRequest $request = null,
    ): string {
        $creatable ??= ['http://localhost/mcp' => [
            'name' => 'Test MCP',
            'scopes' => ['content:read' => 'Read your posts', 'files.read' => 'Read <files>'],
        ]];

        $request ??= (new ServerRequest())->withAttribute('csrfToken', 'csrf-value');

        return (new CakeConnectionsRenderer($request, null))->render(new ConnectionsView(
            new ResourceOwner('1', 'Ada'),
            $connections,
            $tokens,
            $creatable,
            ['http://localhost/mcp' => 'Test MCP'],
            '/oauth/connections',
            'form-token',
            90,
            $enabled,
            'test_pat_secret',
        ));
    }

    /**
     * @param \CakeDC\OAuth\Server\Client\Client $client Client.
     * @return \CakeDC\OAuth\Server\Connections\Connection
     */
    private function connection(Client $client): Connection
    {
        return new Connection(
            'fam-1',
            $client,
            'http://localhost/mcp',
            ['content:read'],
            new DateTimeImmutable('2026-01-02 03:04:05'),
            null,
        );
    }

    /**
     * @return \CakeDC\OAuth\Server\Token\Token
     */
    private function personalToken(): Token
    {
        return new Token(
            'tok-1',
            'hash',
            TokenType::Personal,
            'fam-2',
            null,
            '1',
            SubjectType::User,
            'http://localhost/mcp',
            ['content:read'],
            new DateTimeImmutable(),
            new DateTimeImmutable('2026-05-06 07:08:09'),
            'My <laptop>',
        );
    }

    /**
     * @return void
     */
    public function testTheConsentPage(): void
    {
        $html = $this->consent();

        $this->assertStringContainsString('Claude &lt;AI&gt; wants to access Test MCP', $html);
        $this->assertStringContainsString('not verified', $html);
        $this->assertStringContainsString('Signed in as Ada.', $html);
        $this->assertStringContainsString('Read your posts', $html);
        $this->assertStringContainsString('Stay connected', $html);
        $this->assertStringContainsString('action="/oauth/authorize"', $html);
        $fields = Html::hiddenFields($html);
        $this->assertSame('abc', $fields['client_id']);
        $this->assertSame('t', $fields['consent_token']);
        $this->assertArrayHasKey('_csrfToken', $fields);
        $this->assertStringContainsString('name="decision" value="approve"', $html);
        $this->assertStringContainsString('name="decision" value="deny"', $html);
        $this->assertStringContainsString('<title>Authorize Claude &lt;AI&gt;</title>', $html);
        $this->assertStringNotContainsString('Claude <AI>', $html);
    }

    /**
     * @return void
     */
    public function testAMetadataDocumentClientIsHeadlinedByItsHostNotItsName(): void
    {
        $client = $this->client(ClientType::MetadataDocument, 'https://app.example.com/cimd.json', 'Your Bank');
        $html = $this->consent($client);

        $this->assertStringContainsString('app.example.com wants to access Test MCP', $html);
        $this->assertStringContainsString('<title>Authorize app.example.com</title>', $html);
        $this->assertStringContainsString('The request comes from app.example.com. Your answer is sent to claude.ai.', $html);
        $this->assertStringNotContainsString('Your Bank', $html);
        $this->assertStringNotContainsString('not verified', $html);
    }

    /**
     * @return void
     */
    public function testARegisteredClientIsNamedAndNotMarkedUnverified(): void
    {
        $html = $this->consent($this->client(ClientType::Registered, 'abc', 'Acme CLI'));

        $this->assertStringContainsString('Acme CLI wants to access Test MCP', $html);
        $this->assertStringNotContainsString('not verified', $html);
    }

    /**
     * @return void
     */
    public function testTheLoopbackWarningAndTheOfflineLine(): void
    {
        $client = $this->client(ClientType::Dynamic, 'abc', 'CLI', ['http://127.0.0.1:8123/cb']);
        $html = $this->consent($client, false);

        $this->assertStringContainsString(
            'Only continue if you just started this from an application on this computer: '
            . 'any program on this computer can use this address.',
            $html,
        );
        $this->assertStringNotContainsString('Stay connected', $html);
        $this->assertStringContainsString('Stay connected', $this->consent($client, true));
    }

    /**
     * @return void
     */
    public function testConsentEscapesHostileValues(): void
    {
        $client = $this->client(ClientType::Dynamic, 'abc', '"><script>alert(1)</script>');
        $html = (new CakeConsentRenderer(new ServerRequest(), null))->render(new ConsentView(
            $client,
            new ResourceOwner('1', '<b>Eve</b>'),
            new ProtectedResource('http://localhost/mcp', '<i>Res</i>', ['x' => 'd']),
            ['x' => '<u>desc</u>'],
            false,
            self::CALLBACK,
            '/oauth/authorize',
            ['a"b' => '"><img src=x>'],
        ));

        $this->assertStringNotContainsString('<script>', $html);
        $this->assertStringNotContainsString('<b>Eve', $html);
        $this->assertStringNotContainsString('<i>Res', $html);
        $this->assertStringNotContainsString('<u>desc', $html);
        $this->assertStringNotContainsString('<img src=x>', $html);
        $this->assertSame('"><img src=x>', Html::hiddenFields($html)['a"b']);
        $this->assertStringNotContainsString('name="a"b"', $html);
    }

    /**
     * @return void
     */
    public function testScopeDescriptionsAreTranslatedAtRenderTimeInTheDefaultDomain(): void
    {
        $package = new Package('default');
        $package->setMessages(['Read your posts' => 'Lee tus publicaciones']);
        I18n::setTranslator('default', fn(): Package => $package, 'fr');

        $this->assertStringContainsString('Lee tus publicaciones', $this->withLocale('fr', fn() => $this->consent()));
        $this->assertStringContainsString('Read your posts', $this->consent());
        $this->assertStringContainsString(
            'Lee tus publicaciones',
            $this->withLocale('fr', fn() => $this->connections()),
        );
    }

    /**
     * @return void
     */
    public function testPluginStringsAreTranslated(): void
    {
        $this->assertStringContainsString('Autorizar a', $this->withLocale('es', fn() => $this->consent()));
        $this->assertStringContainsString('Seguir conectada', $this->withLocale('es', fn() => $this->consent()));
    }

    /**
     * @return void
     */
    public function testTheAppsPoFileOverridesThePluginMessages(): void
    {
        $html = $this->withLocale('pt', fn() => $this->consent());

        $this->assertStringContainsString('Permitir (app)', $html);
        $this->assertStringContainsString('Deny', $html);
    }

    /**
     * @return void
     */
    public function testAnAppLayoutThatPrintsTheTitleRawCannotBeInjected(): void
    {
        $name = '</title><h1>Your Bank</h1><form action="https://evil.example">';
        $client = $this->client(ClientType::Dynamic, 'abc', $name);
        $request = (new ServerRequest())->withAttribute('csrfToken', 'csrf-value');
        $html = (new CakeConsentRenderer($request, 'raw_title'))->render(new ConsentView(
            $client,
            new ResourceOwner('1', 'Ada'),
            $this->resource(),
            ['content:read' => 'Read your posts'],
            false,
            self::CALLBACK,
            '/oauth/authorize',
            ['client_id' => 'abc'],
        ));

        $this->assertStringNotContainsString('<h1>Your Bank', $html);
        $this->assertStringNotContainsString('<form action="https://evil.example"', $html);
        $this->assertStringContainsString('&lt;/title&gt;&lt;h1&gt;Your Bank&lt;/h1&gt;', $html);
        $this->assertSame(1, substr_count($html, '<title>'));
        $this->assertSame(1, substr_count($html, '<form '));

        $error = (new CakeErrorPageRenderer($request, 'raw_title'))->render(OAuthException::invalidRequest('x'));
        $this->assertStringContainsString('<title>Authorization failed</title>', $error);
        $connections = (new CakeConnectionsRenderer($request, 'raw_title'))->render(new ConnectionsView(
            new ResourceOwner('1', 'Ada'),
            [],
            [],
            [],
            [],
            '/oauth/connections',
            'f',
            90,
            false,
        ));
        $this->assertStringContainsString('<title>Connected applications</title>', $connections);
    }

    /**
     * @param string $locale Locale.
     * @param callable $callback Work.
     * @return string
     */
    private function withLocale(string $locale, callable $callback): string
    {
        $previous = I18n::getLocale();
        I18n::setLocale($locale);
        try {
            return $callback();
        } finally {
            I18n::setLocale($previous);
        }
    }

    /**
     * @return void
     */
    public function testTheConsentFormActionCarriesTheBasePath(): void
    {
        $request = (new ServerRequest(['base' => '/shop', 'webroot' => '/shop/']))
            ->withAttribute('csrfToken', 'csrf-value');
        $html = $this->consent(null, true, '/oauth/authorize', $request);

        $this->assertStringContainsString('action="/shop/oauth/authorize"', $html);
        $this->assertStringNotContainsString('action="/oauth/authorize"', $html);
    }

    /**
     * @return void
     */
    public function testTheConnectionsPage(): void
    {
        $html = $this->connections();

        $this->assertStringContainsString('No application is connected.', $html);
        $this->assertStringContainsString('test_pat_secret', $html);
        $this->assertStringContainsString('name="scope:content:read"', $html);
        $this->assertSame('form-token', Html::hiddenFields($html, 'form_token')['form_token']);
    }

    /**
     * @return void
     */
    public function testDottedScopeNamesArePostedExactly(): void
    {
        $html = $this->connections();

        $this->assertStringContainsString('name="scope:files.read"', $html);
        $this->assertStringNotContainsString('scope:files[read]', $html);
        $this->assertStringContainsString('Read &lt;files&gt;', $html);
        $fields = Html::hiddenFields($html, 'action');
        $this->assertSame('create_token', $fields['action']);
        $this->assertSame('csrf-value', $fields['_csrfToken']);
        $this->assertSame('form-token', $fields['form_token']);
        $this->assertStringContainsString('name="name"', $html);
        $this->assertStringContainsString('name="resource"', $html);
        $this->assertStringContainsString('name="days"', $html);
        $this->assertStringContainsString('max="90"', $html);
    }

    /**
     * @return void
     */
    public function testConnectionsRevokeFormsAndClientCells(): void
    {
        $html = $this->connections([
            $this->connection($this->client(ClientType::MetadataDocument, 'https://CIMD.example.com/c.json', 'Your Bank')),
            $this->connection($this->client(ClientType::Dynamic, 'd', 'Dyn <x>')),
        ], [$this->personalToken()]);

        $this->assertStringContainsString('cimd.example.com', $html);
        $this->assertStringNotContainsString('Your Bank', $html);
        $this->assertStringContainsString('Dyn &lt;x&gt;', $html);
        $this->assertStringContainsString('Unverified: this application registered itself.', $html);
        $this->assertStringContainsString('2026-01-02 03:04 UTC', $html);
        $this->assertStringContainsString('Never', $html);
        $this->assertStringContainsString('My &lt;laptop&gt;', $html);
        $this->assertSame('revoke_connection', Html::hiddenFields($html, 'family_id')['action']);
        $this->assertSame('fam-1', Html::hiddenFields($html, 'family_id')['family_id']);
        $this->assertSame('revoke_token', Html::hiddenFields($html, 'token_id')['action']);
        $this->assertSame('tok-1', Html::hiddenFields($html, 'token_id')['token_id']);
        $this->assertSame('form-token', Html::hiddenFields($html, 'token_id')['form_token']);
        $this->assertSame('csrf-value', Html::hiddenFields($html, 'family_id')['_csrfToken']);
        $this->assertSame('csrf-value', Html::hiddenFields($html, 'token_id')['_csrfToken']);
    }

    /**
     * @return void
     */
    public function testPersonalTokensStayListedAndRevocableWhenTheFeatureIsOff(): void
    {
        $html = $this->connections([], [$this->personalToken()], [], false);

        $this->assertStringContainsString('Personal access tokens', $html);
        $this->assertStringContainsString('My &lt;laptop&gt;', $html);
        $this->assertSame('revoke_token', Html::hiddenFields($html, 'token_id')['action']);
        $this->assertStringNotContainsString('create_token', $html);

        $none = $this->connections([], [], [], false);
        $this->assertStringNotContainsString('Personal access tokens', $none);
    }

    /**
     * @return void
     */
    public function testConnectionsFormsCarryTheBasePath(): void
    {
        $request = new ServerRequest(['base' => '/shop', 'webroot' => '/shop/']);
        $html = $this->connections([$this->connection($this->client())], [], null, true, $request);

        $this->assertStringContainsString('action="/shop/oauth/connections"', $html);
        $this->assertStringNotContainsString('action="/oauth/connections"', $html);
    }

    /**
     * @return void
     */
    public function testTheRouterContextIsRestoredAfterRendering(): void
    {
        $routed = new ServerRequest(['base' => '/other', 'webroot' => '/other/']);
        Router::setRequest($routed);
        $this->consent(null, true, '/oauth/authorize', new ServerRequest(['base' => '/shop', 'webroot' => '/shop/']));

        $this->assertSame($routed, Router::getRequest());
    }

    /**
     * @return void
     */
    public function testTheErrorPageAndNoLayout(): void
    {
        $html = (new CakeErrorPageRenderer(new ServerRequest(), false))
            ->render(OAuthException::invalidRequest('"redirect_uri" is <wrong>.'));

        $this->assertStringContainsString('Authorization failed', $html);
        $this->assertStringContainsString('&quot;redirect_uri&quot; is &lt;wrong&gt;.', $html);
        $this->assertStringContainsString('invalid_request', $html);
        $this->assertStringNotContainsString('<html', $html);
    }
}
