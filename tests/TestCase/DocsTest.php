<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Test\TestCase;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class DocsTest extends TestCase
{
    /**
     * Every Markdown file of the documentation, README first.
     *
     * @return list<string>
     */
    private static function files(): array
    {
        $root = dirname(__DIR__, 2);

        return array_merge([$root . '/README.md'], glob($root . '/docs/*.md') ?: []);
    }

    private static function docs(): string
    {
        $text = '';
        foreach (self::files() as $file) {
            $text .= "\n" . file_get_contents($file);
        }

        return $text;
    }

    /**
     * @return array<string, array{string}>
     */
    public static function mustBeDocumented(): array
    {
        $items = [
            // Plugin settings.
            'userProvider', 'className', 'table', 'finder', 'displayField', 'canAuthorize', 'forClient', 'login',
            'redirectParam', 'identityAttribute', 'consent', 'layout', 'connections', 'enabled', 'rateLimit',
            'cache', 'services', 'users.resource', 'scopes', 'clock', 'transport', 'dns',
            // Core settings.
            'issuer', 'secret', 'resources', 'defaultResource', 'routePrefix', 'tokenPrefix', 'lifetimes',
            'refreshTokens', 'registration', 'cimd', 'clientCredentials', 'introspection', 'personalTokens',
            'retentionDays', 'refreshReuseGrace', 'personalMax', 'allowPrivateSchemes', 'allowedHosts',
            'initialAccessToken', 'rateLimit.cimd', 'deleteConsentsBySubject', 'family_started_at',
            'revokeAllForSubject',
            // Commands.
            'oauth client add', 'oauth client list', 'oauth client revoke', 'oauth token revoke', 'oauth prune',
            'oauth check', '--consents', '--subject', '--client',
            // Events.
            'OAuthServer.tokenIssued', 'OAuthServer.tokenRevoked', 'OAuthServer.consentGranted',
            'OAuthServer.clientRegistered', 'OAuthServer.refreshTokenReused', 'OAuthServer.authorizationDenied',
            // Entry points and extension points.
            'OAuthServer::csrfSkip', 'OAuthServer::token', 'OAuthServer::rbacPermissions', 'OAuthServer::server',
            'OAuthServer::forRequest', 'OAuthServer::reset', 'OAuthServer::pageCsp', 'CakeDC/OAuthServer.Token',
            'OAuthServerToken', 'RbacPermissionsProvider', 'OAuthIdentity', 'OAuthTestTrait', 'oauthTokenFor',
            'withOAuthToken', 'actAsOAuth', 'templates/plugin/CakeDC/OAuthServer', 'oauth_server.po',
            'migrations migrate -p CakeDC/OAuthServer', 'CakeDC/Users', 'trustProxy', 'setTrustedProxies',
            'resourceMetadataUrl', 'skipTwoFactorVerify', 'requireIdentity', '160.79.104.0/21', 'utf8mb4_bin',
            'Auth.Authenticators', 'CakeDC/Auth.permissions', 'permissions_provider_class',
            'mcpTokenValidator', 'cakedc/oauth-server',
        ];

        return array_combine($items, array_map(fn(string $item): array => [$item], $items));
    }

    #[DataProvider('mustBeDocumented')]
    public function testIsDocumented(string $item): void
    {
        $this->assertStringContainsString($item, self::docs());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function pages(): array
    {
        $pages = [];
        foreach (glob(dirname(__DIR__, 2) . '/docs/*.md') ?: [] as $file) {
            $pages[basename($file)] = [basename($file)];
        }

        return $pages;
    }

    #[DataProvider('pages')]
    public function testEveryPageIsLinkedFromTheReadmeAndTheIndex(string $page): void
    {
        $root = dirname(__DIR__, 2);
        $this->assertStringContainsString('docs/' . $page, (string)file_get_contents($root . '/README.md'));
        if ($page !== 'index.md') {
            $this->assertStringContainsString('(' . $page . ')', (string)file_get_contents($root . '/docs/index.md'));
        }
    }

    public function testEveryExpectedPageExists(): void
    {
        $expected = [
            'index', 'installation', 'configuration', 'users', 'cakedc-users', 'protecting-apis', 'pages',
            'commands', 'events', 'testing', 'mcp', 'deployment', 'security', 'troubleshooting',
        ];
        foreach ($expected as $page) {
            $this->assertFileExists(dirname(__DIR__, 2) . '/docs/' . $page . '.md');
        }
    }

    public function testNoEmDashes(): void
    {
        $this->assertStringNotContainsString("\u{2014}", self::docs());
        $this->assertStringNotContainsString("\u{2014}", $this->changelog());
    }

    public function testNoEnDashes(): void
    {
        $this->assertStringNotContainsString("\u{2013}", self::docs());
        $this->assertStringNotContainsString("\u{2013}", $this->changelog());
    }

    public function testChangelogHasTheFirstRelease(): void
    {
        $this->assertStringContainsString('1.0.0-beta1 (unreleased)', $this->changelog());
    }

    private function changelog(): string
    {
        return (string)file_get_contents(dirname(__DIR__, 2) . '/CHANGELOG.md');
    }

    private static function anchor(string $heading): string
    {
        $heading = strtolower(str_replace('`', '', trim($heading)));

        return str_replace(' ', '-', (string)preg_replace('/[^\w\- ]/', '', $heading));
    }

    public function testEveryRelativeLinkAndAnchorResolves(): void
    {
        $anchors = [];
        $texts = [];
        foreach (self::files() as $file) {
            $text = (string)preg_replace('/```.*?```/s', '', (string)file_get_contents($file));
            $texts[$file] = $text;
            preg_match_all('/^#+\s+(.*)$/m', $text, $matches);
            $anchors[$file] = array_map(self::anchor(...), $matches[1]);
        }
        $checked = 0;
        foreach ($texts as $file => $text) {
            preg_match_all('/\]\(([^)\s]+)\)/', $text, $links);
            foreach ($links[1] as $link) {
                if (str_starts_with($link, 'http')) {
                    continue;
                }
                [$path, $anchor] = array_pad(explode('#', $link, 2), 2, '');
                $target = $path === '' ? $file : (string)realpath(dirname($file) . '/' . $path);
                $this->assertFileExists($target, basename($file) . ' links to ' . $link);
                if ($anchor !== '' && str_ends_with($target, '.md')) {
                    $this->assertContains($anchor, $anchors[$target] ?? [], basename($file) . ' links to ' . $link);
                }
                $checked++;
            }
        }
        $this->assertGreaterThan(0, $checked);
    }
}
