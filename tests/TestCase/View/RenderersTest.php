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
use CakeDC\OAuth\Server\View\RedirectNoticeRendererInterface;
use CakeDC\OAuth\Server\View\RedirectNoticeView;
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
        ?string $redirect = null,
        bool $approvedBefore = false,
    ): string {
        $request ??= (new ServerRequest())->withAttribute('csrfToken', 'csrf-value');
        $client ??= $this->client();

        return (new CakeConsentRenderer($request, null))->render(new ConsentView(
            $client,
            new ResourceOwner('1', 'Ada'),
            $this->resource(),
            ['content:read' => 'Read your posts'],
            $offline,
            $redirect ?? $client->redirectUris[0],
            $action,
            ['client_id' => 'abc', 'consent_token' => 't'],
            $approvedBefore,
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

        // A self-registered client is headlined by the host its answer goes to; its name is only quoted.
        $this->assertStringContainsString('<h1>claude.ai wants to access Test MCP</h1>', $html);
        $this->assertStringContainsString(
            'It calls itself <q>Claude &lt;AI&gt;</q>. Anyone can choose that name.',
            $html,
        );
        $this->assertStringContainsString('The request comes from claude.ai. Your answer is sent to claude.ai.', $html);
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
        $this->assertStringContainsString('<title>Authorize claude.ai</title>', $html);
        $this->assertStringNotContainsString('Claude <AI>', $html);
        $this->assertStringNotContainsString('approved this application before', $html);
    }

    /**
     * A name and the registered redirect URIs are chosen by a self-registered client: neither may make the page
     * read like another client. The title, the heading and the "from" line use the host the answer goes to.
     *
     * @return void
     */
    public function testADynamicClientCannotBorrowAnotherClientsNameOrListedHost(): void
    {
        $client = $this->client(ClientType::Dynamic, 'abc', 'claude.ai', [self::CALLBACK, 'https://evil.example/cb']);
        $html = $this->consent($client, true, '/oauth/authorize', null, 'https://evil.example/cb');

        $this->assertStringContainsString('<title>Authorize evil.example</title>', $html);
        $this->assertStringContainsString('<h1>evil.example wants to access Test MCP</h1>', $html);
        $this->assertStringContainsString(
            'The request comes from evil.example. Your answer is sent to evil.example.',
            $html,
        );
        $this->assertStringContainsString('It calls itself <q>claude.ai</q>. Anyone can choose that name.', $html);
        $this->assertStringNotContainsString('claude.ai wants', $html);
        $this->assertStringNotContainsString('from claude.ai', $html);
        $this->assertStringNotContainsString('Authorize claude.ai', $html);
    }

    /**
     * Anyone can claim a private-use scheme, `claude.ai:` included: such a client is "an application on this
     * computer", and the scheme only says where the answer goes.
     *
     * @return void
     */
    public function testAPrivateSchemeIsShownAsTheDestinationAndNeverAsTheRequester(): void
    {
        $client = $this->client(ClientType::Dynamic, 'abc', 'Claude', ['claude.ai:/oauth/callback']);
        $html = $this->consent($client);

        $this->assertStringContainsString('<title>Authorize An application on this computer</title>', $html);
        $this->assertStringContainsString('<h1>An application on this computer wants to access Test MCP</h1>', $html);
        $this->assertStringContainsString(
            'The request comes from an application on this computer. Your answer is sent to claude.ai:.',
            $html,
        );
        $this->assertStringContainsString('It calls itself <q>Claude</q>. Anyone can choose that name.', $html);
        $this->assertStringContainsString('any program on this computer can use this address', $html);
        $this->assertStringNotContainsString('Claude wants', $html);
        $this->assertStringNotContainsString('claude.ai wants', $html);
    }

    /**
     * The boundary of a declared name is drawn in markup, so a name with quote characters cannot close it and go
     * on as if the server were speaking.
     *
     * @return void
     */
    public function testTheDeclaredNameIsQuotedInMarkup(): void
    {
        $html = $this->consent($this->client(ClientType::Dynamic, 'abc', 'Claude". Verified publisher. "'));

        $this->assertStringContainsString(
            'It calls itself <q>Claude&quot;. Verified publisher. &quot;</q>. Anyone can choose that name.',
            $html,
        );
        $this->assertSame(1, substr_count($html, '<q>'));
    }

    /**
     * A translation that drops the placeholder must not hide the declared name.
     *
     * @return void
     */
    public function testATranslationWithoutThePlaceholderStillShowsTheName(): void
    {
        $package = new Package('default');
        $package->setMessages(['It calls itself {0}. Anyone can choose that name.' => 'Zelfgekozen naam.']);
        // A locale no other test uses: translators are cached per domain and locale for the whole run.
        I18n::setTranslator('oauth_server', fn(): Package => $package, 'nl');

        $html = $this->withLocale('nl', fn() => $this->consent());

        $this->assertStringContainsString('Zelfgekozen naam. <q>Claude &lt;AI&gt;</q>', $html);
    }

    /**
     * A name that only repeats the host is not quoted again.
     *
     * @return void
     */
    public function testANameThatIsTheHostIsNotRepeated(): void
    {
        $html = $this->consent($this->client(ClientType::Dynamic, 'abc', 'claude.ai'));

        $this->assertStringContainsString('<h1>claude.ai wants to access Test MCP</h1>', $html);
        $this->assertStringNotContainsString('<q>', $html);
        $this->assertStringContainsString('not verified', $html);
    }

    /**
     * A remembered consent of a client whose identity cannot be assured: the page says so.
     *
     * @return void
     */
    public function testTheApprovedBeforeLine(): void
    {
        $client = $this->client(ClientType::Dynamic, 'abc', 'CLI', ['http://127.0.0.1:8123/cb']);
        $html = $this->consent($client, false, '/oauth/authorize', null, null, true);

        $this->assertStringContainsString(
            'You approved this application before. It is asked again because its identity cannot be confirmed: '
            . 'only continue if you started this yourself.',
            $html,
        );
        $this->assertStringContainsString('any program on this computer can use this address', $html);
        $this->assertStringNotContainsString('approved this application before', $this->consent($client, false));
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
        $this->assertStringContainsString('It calls itself <q>Dyn &lt;x&gt;</q>. Anyone can choose that name.', $html);
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
     * On the connections page a self-registered client is labelled by the hosts of its redirect URIs, never by
     * its name: a fixed text for private-use schemes, both for a mixed client.
     *
     * @return void
     */
    public function testDynamicClientsAreLabelledByTheirRedirectHosts(): void
    {
        $cell = function (array $redirects, string $name): string {
            $html = $this->connections([$this->connection($this->client(ClientType::Dynamic, 'd', $name, $redirects))]);
            preg_match('#<tr>\s*<td>(.*?)</td>#s', $html, $matches);

            return trim(preg_replace('/\s+/', ' ', $matches[1] ?? '') ?? '');
        };

        $web = $cell(['https://a.example/cb', 'https://B.example/cb', 'https://a.example/other'], 'Claude');
        $this->assertStringStartsWith('a.example, b.example<br>', $web);
        $this->assertStringContainsString('It calls itself <q>Claude</q>.', $web);
        $this->assertStringContainsString('Unverified: this application registered itself.', $web);

        $local = $cell(['claude.ai:/cb'], 'Claude');
        $this->assertStringStartsWith('An application on this computer<br>', $local);
        $this->assertStringContainsString('<q>Claude</q>', $local);

        $mixed = $cell(['https://app.example/cb', 'com.example.app:/cb'], 'Claude');
        $this->assertStringStartsWith('app.example and an application on this computer<br>', $mixed);
        $this->assertStringContainsString('<q>Claude</q>', $mixed);

        $same = $cell(['https://app.example/cb'], 'app.example');
        $this->assertStringStartsWith('app.example<br>', $same);
        $this->assertStringNotContainsString('<q>', $same);
        $this->assertStringContainsString('Unverified', $same);

        foreach ([$web, $local, $mixed] as $html) {
            $this->assertStringNotContainsString('Claude<br>', $html);
            $this->assertStringStartsNotWith('Claude', $html);
        }
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
            ->render(OAuthException::invalidRequest("'redirect_uri' is <wrong>."));

        $this->assertStringContainsString('Authorization failed', $html);
        $this->assertStringContainsString('&#039;redirect_uri&#039; is &lt;wrong&gt;.', $html);
        $this->assertStringContainsString('invalid_request', $html);
        $this->assertStringNotContainsString('<html', $html);
        $this->assertStringNotContainsString('<a ', $html);
    }

    /**
     * The page shown instead of a redirect to an untrusted client: the destination host and a plain link the person
     * may follow, never followed by the page itself.
     *
     * @return void
     */
    public function testTheRedirectNoticeNamesTheHostAndOnlyLinksToIt(): void
    {
        $renderer = new CakeErrorPageRenderer(new ServerRequest(), null);
        $this->assertInstanceOf(RedirectNoticeRendererInterface::class, $renderer);
        $continue = 'https://evil.example/login?error=invalid_request&state=%22%3E%3Cscript%3E&x="><script>';
        $html = $renderer->renderRedirectNotice(new RedirectNoticeView(
            OAuthException::invalidRequest('Something is <wrong>.'),
            $this->client(ClientType::Dynamic, 'abc', 'claude.ai', ['https://evil.example/login']),
            'https://evil.example/login',
            $continue,
        ));

        $this->assertStringContainsString('<h1>Authorization failed</h1>', $html);
        $this->assertStringContainsString('Something is &lt;wrong&gt;.', $html);
        $this->assertStringContainsString(
            'The application asked to send this answer to evil.example. This server cannot confirm that evil.example '
            . 'belongs to it: only continue if you trust it.',
            $html,
        );
        $this->assertStringContainsString(
            '<a href="' . h($continue) . '" rel="noreferrer">Continue to evil.example</a>',
            $html,
        );
        $this->assertStringNotContainsString('<script', $html);
        $this->assertStringNotContainsString('http-equiv', $html);
        $this->assertStringNotContainsString('claude.ai', $html);
        $this->assertSame(1, substr_count($html, '<a '));
    }

    /**
     * For a private-use redirect URI the notice names the scheme, which is all that can be said about it.
     *
     * @return void
     */
    public function testTheRedirectNoticeOfAPrivateSchemeNamesTheScheme(): void
    {
        $html = (new CakeErrorPageRenderer(new ServerRequest(), false))->renderRedirectNotice(new RedirectNoticeView(
            OAuthException::invalidRequest('x'),
            null,
            'com.example.app:/oauth/callback',
            'com.example.app:/oauth/callback?error=invalid_request',
        ));

        $this->assertStringContainsString('Continue to com.example.app:</a>', $html);
        $this->assertStringContainsString('href="com.example.app:/oauth/callback?error=invalid_request"', $html);
    }

    /**
     * @return void
     */
    public function testTheNewLinesAreTranslatedToSpanish(): void
    {
        $consent = $this->withLocale('es', fn() => $this->consent(
            $this->client(ClientType::Dynamic, 'abc', 'Claude', ['claude.ai:/cb']),
            true,
            '/oauth/authorize',
            null,
            null,
            true,
        ));
        $this->assertStringContainsString('Una aplicación de este equipo quiere acceder a Test MCP', $consent);
        $this->assertStringContainsString('Se hace llamar <q>Claude</q>. Cualquiera puede elegir ese nombre.', $consent);
        $this->assertStringContainsString('Ya aprobaste esta aplicación antes.', $consent);

        $notice = $this->withLocale('es', fn() => (new CakeErrorPageRenderer(new ServerRequest(), false))
            ->renderRedirectNotice(new RedirectNoticeView(
                OAuthException::invalidRequest('x'),
                null,
                'https://evil.example/cb',
                'https://evil.example/cb?error=invalid_request',
            )));
        $this->assertStringContainsString('Continuar a evil.example', $notice);
        $this->assertStringContainsString('La aplicación pidió enviar esta respuesta a evil.example.', $notice);

        $connections = $this->withLocale('es', fn() => $this->connections([
            $this->connection($this->client(ClientType::Dynamic, 'd', 'Claude', ['https://a.example/cb', 'x.y:/cb'])),
        ]));
        $this->assertStringContainsString('a.example y una aplicación de este equipo', $connections);
    }
}
