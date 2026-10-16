<?php
declare(strict_types=1);

namespace TestApp\Controller;

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
}
