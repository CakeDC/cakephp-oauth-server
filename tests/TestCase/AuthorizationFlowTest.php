<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase;

use Cake\Core\Configure;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use CakeDC\OAuth\Server\Grant\Pkce;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\FakeDns;
use CakeDC\OAuthServer\Test\Support\FakeTransport;
use CakeDC\OAuthServer\Test\Support\Fixtures;
use CakeDC\OAuthServer\Test\Support\Html;

/**
 * The authorization endpoint through the plugin's pages (RFC 9700 section 4.11.2, RFC 8252 section 8.6): no
 * redirect before the login, a notice page instead of a redirect to a client nobody vouches for, a remembered
 * consent that does not answer for a client whose identity cannot be confirmed, and pages that headline a
 * self-registered client by the host its answer goes to.
 */
class AuthorizationFlowTest extends TestCase
{
    use IntegrationTestTrait;

    private const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    private const CLAUDE = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
    private const CALLBACK = 'https://claude.ai/api/mcp/auth_callback';
    private const EVIL = 'https://evil.example/login';

    protected array $fixtures = Fixtures::ALL;

    /**
     * @var array<string, mixed>
     */
    private array $settings = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->settings = (array)Configure::read('OAuthServer');
        $transport = new FakeTransport();
        $transport->serve(self::CLAUDE, [
            'client_id' => self::CLAUDE,
            'client_name' => 'Claude',
            'redirect_uris' => [self::CALLBACK],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ]);
        Configure::write('OAuthServer.cimd', ['enabled' => true]);
        Configure::write('OAuthServer.services', ['transport' => $transport, 'dns' => new FakeDns()]);
        OAuthServer::reset();
    }

    protected function tearDown(): void
    {
        Configure::write('OAuthServer', $this->settings);
        OAuthServer::reset();
        parent::tearDown();
    }

    /**
     * Registers a client through /oauth/register; returns its client_id.
     *
     * @param list<string> $redirects Redirect URIs.
     * @param string $name The name it gives itself.
     * @return string
     */
    private function register(array $redirects, string $name = 'claude.ai'): string
    {
        $this->configRequest(['headers' => ['Content-Type' => 'application/json']]);
        $this->post('/oauth/register', (string)json_encode([
            'client_name' => $name,
            'redirect_uris' => $redirects,
            'token_endpoint_auth_method' => 'none',
        ]));
        $this->assertResponseCode(201);
        $this->_request = [];

        return (string)json_decode((string)$this->_response->getBody(), true)['client_id'];
    }

    /**
     * @param array<string, string> $params Parameters to add or replace.
     * @return array<string, string>
     */
    private function params(string $clientId, string $redirect, array $params = []): array
    {
        return $params + [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirect,
            'state' => 's',
            'scope' => 'api',
            'code_challenge' => Pkce::challengeFor(self::VERIFIER),
            'code_challenge_method' => 'S256',
            'resource' => 'http://localhost/api',
        ];
    }

    /**
     * @param array<string, string> $params Parameters to add or replace.
     */
    private function authorize(string $clientId, string $redirect, array $params = []): void
    {
        $this->get('/oauth/authorize?' . http_build_query(
            $this->params($clientId, $redirect, $params),
            '',
            '&',
            PHP_QUERY_RFC3986,
        ));
    }

    /**
     * Shows the consent page as person 1 and answers it.
     */
    private function answer(string $clientId, string $redirect, string $decision = 'approve'): void
    {
        $this->session(['Auth' => ['id' => 1]]);
        $this->authorize($clientId, $redirect);
        $this->assertResponseOk();
        $this->post('/oauth/authorize', $this->consentFields() + ['decision' => $decision]);
    }

    /**
     * The hidden fields of the consent form on the current page, ready to post.
     *
     * @return array<string, string>
     */
    private function consentFields(): array
    {
        $fields = Html::hiddenFields((string)$this->_response->getBody(), 'consent_token');
        unset($fields['_csrfToken']);
        $this->session(['Auth' => ['id' => 1]]);
        $this->enableCsrfToken();

        return $fields;
    }

    private function codes(): int
    {
        return $this->fetchTable('CakeDC/OAuthServer.OauthAuthorizationCodes')->find()->count();
    }

    public function testAnAnonymousVisitorIsSentToTheLoginAndNeverToAnUntrustedClient(): void
    {
        $clientId = $this->register([self::EVIL]);

        $this->authorize($clientId, self::EVIL, ['response_type' => 'x']);

        $this->assertResponseCode(302);
        $location = $this->_response->getHeaderLine('Location');
        $this->assertStringStartsWith('/login?redirect=', $location);
        $this->assertStringNotContainsString('evil.example', rawurldecode(explode('?', $location, 2)[0]));
        parse_str((string)parse_url($location, PHP_URL_QUERY), $query);
        $this->assertIsString($query['redirect']);
        $this->assertStringStartsWith('/oauth/authorize?', $query['redirect']);
        $this->assertStringContainsString('response_type=x', $query['redirect']);
    }

    public function testAnAnonymousVisitorIsSentToTheLoginForARegisteredClientToo(): void
    {
        $client = OAuthServer::server()->clientRegistrar()->create('App', ['https://app.example.com/cb'], false);

        $this->authorize($client['client']->clientId, 'https://app.example.com/cb', ['response_type' => 'x']);

        $this->assertResponseCode(302);
        $this->assertStringStartsWith('/login?redirect=', $this->_response->getHeaderLine('Location'));
    }

    public function testAnAnonymousPostWithARedirectableErrorGetsThePlainErrorPage(): void
    {
        $clientId = $this->register([self::EVIL]);
        $this->enableCsrfToken();

        $this->post('/oauth/authorize', $this->params($clientId, self::EVIL, ['response_type' => 'x']));

        $this->assertResponseCode(400);
        $this->assertSame('', $this->_response->getHeaderLine('Location'));
        $this->assertResponseContains('Authorization failed');
        $this->assertResponseNotContains('<a ');
    }

    public function testASignedInPersonIsShownWhereAnUntrustedClientWouldSendThem(): void
    {
        $clientId = $this->register([self::EVIL]);
        $this->session(['Auth' => ['id' => 1]]);

        $this->authorize($clientId, self::EVIL, ['response_type' => 'x']);

        $this->assertResponseCode(400);
        $this->assertSame('', $this->_response->getHeaderLine('Location'));
        $body = (string)$this->_response->getBody();
        $this->assertStringContainsString('<title>Authorization failed</title>', $body);
        $this->assertStringContainsString(
            'The application asked to send this answer to evil.example. This server cannot confirm that evil.example '
            . 'belongs to it: only continue if you trust it.',
            $body,
        );
        $this->assertSame(1, preg_match('#<a href="([^"]+)" rel="noreferrer">Continue to evil.example</a>#', $body, $link));
        $continue = html_entity_decode($link[1], ENT_QUOTES | ENT_HTML5);
        $this->assertStringStartsWith(self::EVIL . '?', $continue);
        parse_str((string)parse_url($continue, PHP_URL_QUERY), $query);
        $this->assertSame('unsupported_response_type', $query['error'] ?? null);
        $this->assertSame('s', $query['state'] ?? null);
        $this->assertSame('http://localhost', $query['iss'] ?? null);
        $this->assertStringNotContainsString('http-equiv', $body);
        $this->assertStringNotContainsString('<script', $body);
    }

    public function testASignedInPostForAnUntrustedClientGetsTheNoticeToo(): void
    {
        $clientId = $this->register([self::EVIL]);
        $this->session(['Auth' => ['id' => 1]]);
        $this->enableCsrfToken();

        $this->post('/oauth/authorize', $this->params($clientId, self::EVIL, ['response_type' => 'x']));

        $this->assertResponseCode(400);
        $this->assertSame('', $this->_response->getHeaderLine('Location'));
        $this->assertResponseContains('Continue to evil.example</a>');
    }

    public function testAMetadataDocumentClientNobodyApprovedGetsTheNotice(): void
    {
        $this->session(['Auth' => ['id' => 1]]);

        $this->authorize(self::CLAUDE, self::CALLBACK, ['code_challenge' => '']);

        $this->assertResponseCode(400);
        $this->assertSame('', $this->_response->getHeaderLine('Location'));
        $this->assertResponseContains('Continue to claude.ai</a>');
    }

    public function testAClientThePersonApprovedGetsItsErrorsBack(): void
    {
        $redirect = 'https://app.example.com/cb';
        $clientId = $this->register([$redirect], 'App');
        $this->answer($clientId, $redirect);
        $this->assertResponseCode(303);

        $this->session(['Auth' => ['id' => 1]]);
        $this->authorize($clientId, $redirect, ['response_type' => 'x']);

        $this->assertResponseCode(302);
        $this->assertStringStartsWith($redirect . '?error=unsupported_response_type', $this->_response->getHeaderLine('Location'));
    }

    public function testARegisteredClientGetsItsErrorsBack(): void
    {
        $client = OAuthServer::server()->clientRegistrar()->create('App', ['https://app.example.com/cb'], false);
        $this->session(['Auth' => ['id' => 1]]);

        $this->authorize($client['client']->clientId, 'https://app.example.com/cb', ['response_type' => 'x']);

        $this->assertResponseCode(302);
        $this->assertStringStartsWith(
            'https://app.example.com/cb?error=unsupported_response_type',
            $this->_response->getHeaderLine('Location'),
        );
    }

    public function testDenyingSendsTheAnswerBackEvenToAnUntrustedClient(): void
    {
        $clientId = $this->register([self::EVIL]);

        $this->answer($clientId, self::EVIL, 'deny');

        $this->assertResponseCode(303);
        $this->assertStringStartsWith(self::EVIL . '?error=access_denied', $this->_response->getHeaderLine('Location'));
    }

    public function testALoopbackClientApprovedBeforeIsAskedAgain(): void
    {
        $redirect = 'http://127.0.0.1:53682/callback';
        $clientId = $this->register([$redirect], 'Claude Code');
        $this->answer($clientId, $redirect);
        $this->assertResponseCode(303);
        $codes = $this->codes();

        $this->session(['Auth' => ['id' => 1]]);
        $this->authorize($clientId, $redirect);

        $this->assertResponseOk();
        $this->assertResponseContains('<h1>127.0.0.1 wants to access Test API</h1>');
        $this->assertResponseContains(
            'You approved this application before. It is asked again because its identity cannot be confirmed: '
            . 'only continue if you started this yourself.',
        );
        $this->assertResponseContains('any program on this computer can use this address');
        $this->assertSame($codes, $this->codes(), 'A code was issued without asking.');

        $this->post('/oauth/authorize', $this->consentFields() + ['decision' => 'approve']);
        $this->assertResponseCode(303);
        $this->assertStringStartsWith($redirect . '?code=', $this->_response->getHeaderLine('Location'));
    }

    public function testAnHttpsClientApprovedBeforeIsNotAskedAgain(): void
    {
        $this->answer(self::CLAUDE, self::CALLBACK);
        $this->assertResponseCode(303);

        $this->session(['Auth' => ['id' => 1]]);
        $this->authorize(self::CLAUDE, self::CALLBACK);

        $this->assertResponseCode(302);
        $this->assertStringStartsWith(self::CALLBACK . '?code=', $this->_response->getHeaderLine('Location'));
    }

    public function testTheConsentPageHeadlinesASelfRegisteredClientByItsRedirectHost(): void
    {
        $clientId = $this->register([self::CALLBACK, 'https://evil.example/cb'], 'claude.ai');
        $this->session(['Auth' => ['id' => 1]]);

        $this->authorize($clientId, 'https://evil.example/cb');

        $this->assertResponseOk();
        $this->assertResponseContains('<title>Authorize evil.example</title>');
        $this->assertResponseContains('<h1>evil.example wants to access Test API</h1>');
        $this->assertResponseContains('The request comes from evil.example. Your answer is sent to evil.example.');
        $this->assertResponseContains('It calls itself <q>claude.ai</q>. Anyone can choose that name.');
        $this->assertResponseNotContains('claude.ai wants');
        $this->assertResponseNotContains('from claude.ai');
    }

    public function testTheConnectionsPageLabelsASelfRegisteredClientByItsRedirectHosts(): void
    {
        $clientId = $this->register(['https://evil.example/cb'], 'claude.ai');
        $this->answer($clientId, 'https://evil.example/cb');
        $this->assertResponseCode(303);
        parse_str((string)parse_url($this->_response->getHeaderLine('Location'), PHP_URL_QUERY), $params);
        $this->_request = [];
        $this->configRequest(['headers' => ['Content-Type' => 'application/x-www-form-urlencoded']]);
        $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $params['code'] ?? '',
            'redirect_uri' => 'https://evil.example/cb',
            'code_verifier' => self::VERIFIER,
            'client_id' => $clientId,
            'resource' => 'http://localhost/api',
        ]);
        $this->assertResponseOk();

        $this->_request = [];
        $this->session(['Auth' => ['id' => 1]]);
        $this->get('/oauth/connections');

        $this->assertResponseOk();
        $body = (string)$this->_response->getBody();
        $this->assertSame(1, preg_match('#<tr>\s*<td>\s*(.*?)</td>#s', $body, $cell));
        $this->assertStringStartsWith('evil.example<br>', trim($cell[1]));
        $this->assertStringContainsString('It calls itself <q>claude.ai</q>.', $cell[1]);
        $this->assertStringContainsString('Unverified: this application registered itself.', $cell[1]);
    }
}
