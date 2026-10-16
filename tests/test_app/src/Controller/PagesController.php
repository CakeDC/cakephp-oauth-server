<?php
declare(strict_types=1);

namespace TestApp\Controller;

use Cake\Core\Configure;
use Cake\Http\Response;
use CakeDC\OAuthServer\OAuthServer;

/**
 * Pages of the test application: a login form and a protected API action.
 */
class PagesController extends AppController
{
    /**
     * @return \Cake\Http\Response
     */
    public function login(): Response
    {
        $this->Authorization->skipAuthorization();

        return $this->response->withStringBody('login form');
    }

    /**
     * @return \Cake\Http\Response
     */
    public function me(): Response
    {
        $this->Authorization->skipAuthorization();
        $identity = $this->Authentication->getIdentity();
        if ($identity === null) {
            return $this->response
                ->withStatus(401)
                ->withType('application/json')
                ->withStringBody('{"error":"unauthorized"}');
        }
        $token = OAuthServer::token($this->request);

        return $this->response->withType('application/json')->withStringBody((string)json_encode([
            'id' => $identity->getIdentifier(),
            'scopes' => $token?->scopes,
        ]));
    }

    /**
     * An MCP endpoint behind the Token authenticator. Without an identity it answers like an MCP server's
     * transport: 401 with the challenge that starts the client's discovery.
     *
     * @return \Cake\Http\Response
     */
    public function mcp(): Response
    {
        $this->Authorization->skipAuthorization();
        $identity = $this->Authentication->getIdentity();
        if ($identity === null) {
            return $this->response
                ->withStatus(401)
                ->withHeader(
                    'WWW-Authenticate',
                    'Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource/mcp"',
                )
                ->withType('application/json')
                ->withStringBody('{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Unauthorized"}}');
        }

        return $this->response->withType('application/json')->withStringBody((string)json_encode([
            'jsonrpc' => '2.0',
            'id' => $identity->getIdentifier(),
            'result' => [],
        ]));
    }

    /**
     * A state-changing session action: it records that it ran.
     *
     * @return \Cake\Http\Response
     */
    public function deleteAccount(): Response
    {
        $this->Authorization->skipAuthorization();
        Configure::write('TestApp.accountDeleted', true);

        return $this->response->withStringBody('deleted ' . (string)$this->Authentication->getIdentity()?->getIdentifier());
    }
}
