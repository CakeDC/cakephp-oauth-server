<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Integration;

use CakeDC\Auth\Rbac\Permissions\ConfigProvider;
use CakeDC\OAuthServer\OAuthServer;

/**
 * The RBAC rules of the application (`config/permissions.php`) with the OAuth endpoint rule in front.
 *
 * cakedc/auth reloads that file over `Configure`, so a rule written there beforehand is lost; the
 * integration sets this class as `Auth.RbacPolicy.adapter.permissions_provider_class` instead.
 *
 * @internal
 */
class RbacPermissionsProvider extends ConfigProvider
{
    /**
     * The application's rules, with the OAuth endpoint rule first.
     *
     * @return array<int|string, array<string, mixed>>
     */
    public function getPermissions(): array
    {
        $rules = OAuthServer::rbacPermissions();

        return array_merge($rules, array_filter(
            parent::getPermissions(),
            static fn(mixed $rule): bool => !in_array($rule, $rules, true),
        ));
    }
}
