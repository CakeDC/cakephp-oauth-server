<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Authenticator;

/**
 * The token authenticator under a name of its own: `CakeDC/OAuthServer.OAuthServerToken`.
 *
 * Authentication collections alias an authenticator by the class name without the plugin, so loading
 * `CakeDC/OAuthServer.Token` next to cakedc/users' own `Token` authenticator fails with "The `Token`
 * alias has already been loaded". The cakedc/users integration loads this class instead.
 */
class OAuthServerTokenAuthenticator extends TokenAuthenticator
{
}
