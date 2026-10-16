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
     * What each page must mention: the page file name maps to items that have to be on that very page.
     *
     * @return array<string, list<string>>
     */
    private static function owners(): array
    {
        return [
            'configuration.md' => array_merge(
                array_map(fn(string $key): string => '`' . $key . '`', [
                    // Plugin settings.
                    'userProvider', 'className', 'table', 'finder', 'displayField', 'canAuthorize', 'forClient',
                    'scopes', 'login', 'redirectParam', 'identityAttribute', 'consent', 'layout', 'connections',
                    'enabled', 'rateLimit', 'cache', 'services', 'clock', 'transport', 'dns', 'users.resource', 'users.paths', 'tokenPaths',
                    // Core settings.
                    'issuer', 'secret', 'resources', 'defaultResource', 'routePrefix', 'tokenPrefix', 'lifetimes',
                    'refreshTokens', 'registration', 'cimd', 'clientCredentials', 'introspection',
                    'personalTokens', 'retentionDays', 'refreshReuseGrace', 'personalMax', 'allowPrivateSchemes',
                    'allowedHosts', 'initialAccessToken',
                ]),
                ['rateLimit.cimd', 'family_started_at'],
            ),
            'commands.md' => [
                'oauth client add', 'oauth client list', 'oauth client revoke', 'oauth token revoke',
                'oauth prune', 'oauth check', '--consents', '--subject', '--client', '--redirect-uri',
                '--confidential', '--grant', '--scope', '--introspection', '--native',
            ],
            'events.md' => [
                'OAuthServer.tokenIssued', 'OAuthServer.tokenRevoked', 'OAuthServer.consentGranted',
                'OAuthServer.clientRegistered', 'OAuthServer.refreshTokenReused',
                'OAuthServer.authorizationDenied',
            ],
            'installation.md' => [
                'OAuthServer::csrfSkip', 'migrations migrate -p CakeDC/OAuthServer', 'CakeDC/OAuthServer.Token',
            ],
            'protecting-apis.md' => [
                'OAuthServer::token', 'OAuthIdentity', 'CakeDC/OAuthServer.Token', 'resourceMetadataUrl',
                'skipTwoFactorVerify', 'requireIdentity',
            ],
            'cakedc-users.md' => [
                'OAuthServer::rbacPermissions', 'OAuthServerToken', 'RbacPermissionsProvider',
                'permissions_provider_class', 'Auth.Authenticators', 'CakeDC/Auth.permissions', 'users.resource',
            ],
            'users.md' => ['--consents', 'deleteConsentsBySubject', 'revokeAllForSubject', 'OrmUserProvider'],
            'pages.md' => [
                'templates/plugin/CakeDC/OAuthServer', 'oauth_server.po', 'OAuthServer::pageCsp',
            ],
            'testing.md' => [
                'OAuthTestTrait', 'oauthTokenFor', 'withOAuthToken', 'actAsOAuth', 'OAuthServer::reset',
            ],
            'mcp.md' => ['mcpTokenValidator', 'cakedc/cakephp-mcp'],
            'deployment.md' => [
                'trustProxy', 'setTrustedProxies', '160.79.104.0/21', 'utf8mb4_bin', 'CHAR(36)',
            ],
            'troubleshooting.md' => ['oauth check', 'OAuthServer::csrfSkip'],
            'index.md' => ['OAuthServer::server', 'OAuthServer::forRequest', 'OAuthServer::reset'],
        ];
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function mustBeDocumented(): array
    {
        $cases = [];
        foreach (self::owners() as $page => $items) {
            foreach ($items as $item) {
                $cases[$page . ': ' . $item] = [$page, $item];
            }
        }

        return $cases;
    }

    #[DataProvider('mustBeDocumented')]
    public function testIsDocumented(string $page, string $item): void
    {
        $text = (string)file_get_contents(dirname(__DIR__, 2) . '/docs/' . $page);
        $this->assertStringContainsString($item, $text, $page . ' must mention ' . $item);
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
        $core = 'https://github.com/CakeDC/oauth-server/blob/1.x/docs/';
        $coreDir = dirname(__DIR__, 2) . '/vendor/cakedc/oauth-server/docs/';
        $anchors = [];
        $texts = [];
        foreach (array_merge(self::files(), glob($coreDir . '*.md') ?: []) as $file) {
            $text = (string)preg_replace('/```.*?```/s', '', (string)file_get_contents($file));
            $texts[$file] = $text;
            preg_match_all('/^#+\s+(.*)$/m', $text, $matches);
            $anchors[$file] = array_map(self::anchor(...), $matches[1]);
        }
        $checked = 0;
        foreach (self::files() as $file) {
            preg_match_all('/\]\(([^)\s]+)\)/', $texts[$file], $links);
            foreach ($links[1] as $link) {
                [$path, $anchor] = array_pad(explode('#', $link, 2), 2, '');
                if (str_starts_with($link, $core)) {
                    $target = $coreDir . substr($path, strlen($core));
                } elseif (str_starts_with($link, 'http')) {
                    continue;
                } else {
                    $target = $path === '' ? $file : (string)realpath(dirname($file) . '/' . $path);
                }
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
