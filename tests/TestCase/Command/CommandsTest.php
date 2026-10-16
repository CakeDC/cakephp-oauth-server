<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase\Command;

use Cake\Console\ConsoleIo;
use Cake\Console\TestSuite\ConsoleIntegrationTestTrait;
use Cake\Console\TestSuite\StubConsoleOutput;
use Cake\Core\Configure;
use Cake\Datasource\ConnectionManager;
use Cake\Log\Log;
use Cake\TestSuite\TestCase;
use Cake\Utility\Security;
use CakeDC\OAuth\Server\Grant\Consent;
use CakeDC\OAuth\Server\Support\Time;
use CakeDC\OAuthServer\Command\OAuthCheckCommand;
use CakeDC\OAuthServer\OAuthServer;
use CakeDC\OAuthServer\Test\Support\Fixtures;

class CommandsTest extends TestCase
{
    use ConsoleIntegrationTestTrait;

    protected array $fixtures = Fixtures::ALL;

    protected function setUp(): void
    {
        parent::setUp();
        OAuthServer::reset();
    }

    protected function tearDown(): void
    {
        // The console runner adds catch-all console engines, which would hide the plugin's own engine
        // from the log tests that run later in the same process.
        foreach (['stdout', 'stderr'] as $name) {
            Log::drop($name);
        }
        parent::tearDown();
        OAuthServer::reset();
    }

    public function testAddsListsAndRevokesClients(): void
    {
        $this->exec(
            'oauth client add "Nightly job" --confidential --grant client_credentials --scope api --introspection',
        );
        $this->assertExitSuccess();
        $this->assertOutputContains('client_id: ');
        $this->assertOutputContains('client_secret: test_cs_');
        preg_match('/client_id: (\S+)/', implode("\n", $this->_out->messages()), $matches);
        $clientId = $matches[1];

        $this->exec('oauth client list');
        $this->assertExitSuccess();
        $this->assertOutputContains('Nightly job');
        $this->assertOutputContains($clientId);

        $this->exec('oauth client revoke ' . $clientId);
        $this->assertExitSuccess();
        $this->assertTrue(OAuthServer::server()->storage()->findClientByClientId($clientId)?->isRevoked());
        $this->exec('oauth client revoke nope');
        $this->assertExitError();
    }

    public function testAddValidatesItsInput(): void
    {
        $this->exec('oauth client add Bad --grant client_credentials');

        $this->assertExitError();
        $this->assertErrorContains('confidential');
    }

    public function testAddPrintsTheCoreMessageForABadRedirectUri(): void
    {
        $this->exec('oauth client add Bad --redirect-uri http://example.com/cb');

        $this->assertExitError();
        $this->assertErrorContains('http');
    }

    public function testAddsPublicClientsWithRedirects(): void
    {
        $this->exec(
            'oauth client add "Desktop app" --native --redirect-uri http://127.0.0.1/cb '
            . '--redirect-uri myapp.example:/cb',
        );

        $this->assertExitSuccess();
        $this->assertOutputNotContains('client_secret');
        preg_match('/client_id: (\S+)/', implode("\n", $this->_out->messages()), $matches);
        $client = OAuthServer::server()->storage()->findClientByClientId($matches[1]);
        $this->assertCount(2, $client->redirectUris);
    }

    public function testRevokesTokensOfAPersonOrAClient(): void
    {
        $server = OAuthServer::server();
        $resource = $server->config()->resources->defaultResource();
        $server->tokenIssuer()->issuePersonal(
            '1',
            $resource,
            ['content:read'],
            'a',
            Time::plus($server->clock()->now(), 3600),
        );

        $this->exec('oauth token revoke --subject 1');
        $this->assertExitSuccess();
        $this->assertOutputContains('Revoked 1 token(s).');
        $this->assertOutputNotContains('consent');

        $this->exec('oauth token revoke');
        $this->assertExitError();
        $this->exec('oauth token revoke --client nope');
        $this->assertExitError();
        $this->exec('oauth token revoke --consents');
        $this->assertExitError();
    }

    public function testRevokingASubjectCanAlsoDeleteItsConsents(): void
    {
        $server = OAuthServer::server();
        $result = $server->clientRegistrar()->create('App', ['https://app.example.com/cb'], false);
        $now = $server->clock()->now();
        $resource = $server->config()->resources->defaultResource();
        $server->storage()->saveConsent(new Consent(
            '00000000-0000-4000-8000-000000000001',
            '1',
            $result['client']->id,
            $resource->identifier,
            ['content:read'],
            $now,
            $now,
        ));

        $this->exec('oauth token revoke --subject 1');
        $this->assertOutputNotContains('consent');
        $this->assertCount(1, $server->storage()->findConsentsBySubject('1'));

        $this->exec('oauth token revoke --subject 1 --consents');

        $this->assertExitSuccess();
        $this->assertOutputContains('Revoked 0 token(s).');
        $this->assertOutputContains('Deleted 1 consent(s).');
        $this->assertSame([], $server->storage()->findConsentsBySubject('1'));
    }

    public function testPrunes(): void
    {
        $this->exec('oauth prune');

        $this->assertExitSuccess();
        $this->assertOutputContains('Deleted 0 codes, 0 tokens and 0 clients.');
    }

    public function testCheckPassesOnTheTestApplication(): void
    {
        $this->exec('oauth check');

        $this->assertExitSuccess();
        foreach (['Configuration', 'Tables', 'Users', 'Login URL', 'CSRF', 'Client metadata documents'] as $check) {
            $this->assertOutputContains('[PASS] ' . $check);
        }
        $this->assertOutputContains('[WARN] Issuer');
        $this->assertOutputContains('[WARN] Rate limiting');
    }

    public function testCheckFailsOnAMisconfiguredUsersTable(): void
    {
        Configure::write('OAuthServer.userProvider.finder', 'nope');

        $this->exec('oauth check');

        $this->assertExitError();
        $this->assertOutputContains('[FAIL] Users');
    }

    public function testCheckReportsAWeakSecretWithoutCrashing(): void
    {
        $salt = Security::getSalt();
        Security::setSalt('short');
        try {
            $this->exec('oauth check');
        } finally {
            Security::setSalt($salt);
        }

        $this->assertExitError();
        $this->assertOutputContains('[FAIL] Secret');
        $this->assertOutputContains('[FAIL] Configuration');
        $this->assertOutputContains('[PASS] Tables');
        $this->assertOutputContains('[WARN] Issuer');
    }

    public function testCheckReportsAMissingBaseUrlWithoutCrashing(): void
    {
        Configure::write('App.fullBaseUrl', false);

        $this->exec('oauth check');

        $this->assertExitError();
        $this->assertOutputContains('[FAIL] Issuer');
        $this->assertOutputContains('App.fullBaseUrl');
        $this->assertOutputContains('[PASS] Tables');
    }

    public function testCheckAcceptsAConfiguredSecret(): void
    {
        $salt = Security::getSalt();
        Security::setSalt('short');
        Configure::write('OAuthServer.secret', str_repeat('s', 40));

        try {
            $this->exec('oauth check');
        } finally {
            Security::setSalt($salt);
        }

        $this->assertExitSuccess();
        $this->assertOutputContains('[PASS] Secret');
        $this->assertOutputNotContains(str_repeat('s', 40));
    }

    public function testCheckFailsOnAnInvalidTokenPrefix(): void
    {
        Configure::write('OAuthServer.tokenPrefix', 'Not Valid!');

        $this->exec('oauth check');

        $this->assertExitError();
        $this->assertOutputContains('[FAIL] Configuration');
    }

    public function testCheckWarnsWhenTheIssuerHasAPathOrDiffersFromTheBase(): void
    {
        Configure::write('OAuthServer.issuer', 'https://example.com/app');

        $this->exec('oauth check');

        $this->assertExitSuccess();
        $this->assertOutputContains('[WARN] Issuer');
        $this->assertOutputContains('has a path');
        $this->assertOutputContains('differs from App.base');
    }

    public function testCheckPassesAHttpsRootIssuer(): void
    {
        Configure::write('OAuthServer.issuer', 'https://example.com');

        $this->exec('oauth check');

        $this->assertOutputContains('[PASS] Issuer');
    }

    public function testCheckWarnsWhenCimdHasNoRateLimitCache(): void
    {
        if (!extension_loaded('curl')) {
            $this->markTestSkipped('ext-curl is not installed.');
        }
        Configure::write('OAuthServer.cimd.enabled', true);

        $this->exec('oauth check');

        $this->assertOutputContains('[WARN] Client metadata documents');
        $this->assertOutputContains('no fetch budget');
    }

    public function testCheckPassesCimdWithARateLimitCache(): void
    {
        if (!extension_loaded('curl')) {
            $this->markTestSkipped('ext-curl is not installed.');
        }
        Configure::write('OAuthServer.cimd.enabled', true);
        Configure::write('OAuthServer.rateLimit.cache', 'default');

        $this->exec('oauth check');

        $this->assertOutputContains('[PASS] Client metadata documents');
        $this->assertOutputContains('[PASS] Rate limiting');
    }

    public function testCheckFailsOnAMissingRateLimitCacheConfiguration(): void
    {
        Configure::write('OAuthServer.rateLimit.cache', 'nope');

        $this->exec('oauth check');

        $this->assertExitError();
        $this->assertOutputContains('[FAIL] Rate limiting');
    }

    public function testCheckFailsWhenTheFamilyColumnIsMissing(): void
    {
        $connection = ConnectionManager::get('default');
        $connection->execute('ALTER TABLE oauth_tokens DROP COLUMN family_started_at');
        try {
            $this->exec('oauth check');
        } finally {
            $connection->execute('ALTER TABLE oauth_tokens ADD COLUMN family_started_at DATETIME NULL');
        }

        $this->assertExitError();
        $this->assertOutputContains('[FAIL] Tables');
        $this->assertOutputContains('family_started_at');
    }

    public function testCheckReportsTheLoggingEngine(): void
    {
        $this->exec('oauth check');

        $this->assertOutputContains('[PASS] Logging: the "oauth" log engine is configured');
    }

    public function testCheckHintsAtCopyingTheMigrationWhenATableIsMissing(): void
    {
        $connection = ConnectionManager::get('default');
        $connection->execute('ALTER TABLE oauth_consents RENAME TO oauth_consents_gone');
        try {
            $this->exec('oauth check');
        } finally {
            $connection->execute('ALTER TABLE oauth_consents_gone RENAME TO oauth_consents');
        }

        $this->assertExitError();
        $this->assertOutputContains('[FAIL] Tables: missing oauth_consents; copy the plugin migration');
    }

    public function testListShowsClientNamesLiterally(): void
    {
        $name = '<error>boom</error> <text-right>x</text-right> tail';
        OAuthServer::server()->clientRegistrar()->create($name, ['https://app.example.com/cb'], false);

        $this->exec('oauth client list');

        $this->assertExitSuccess();
        $this->assertOutputContains($name);
    }

    public function testCheckWarnsWhenNoEngineHandlesTheOauthScope(): void
    {
        $saved = [];
        foreach (Log::configured() as $name) {
            $saved[$name] = Log::getConfig($name);
            Log::drop($name);
        }
        $out = new StubConsoleOutput();
        try {
            // Run the command directly: booting the plugin registers its own engine.
            (new OAuthCheckCommand())->run([], new ConsoleIo($out, new StubConsoleOutput()));
        } finally {
            foreach (Log::configured() as $name) {
                Log::drop($name);
            }
            foreach ($saved as $name => $config) {
                Log::setConfig($name, $config);
            }
        }

        $this->assertStringContainsString('[WARN] Logging', implode("\n", $out->messages()));
    }
}
