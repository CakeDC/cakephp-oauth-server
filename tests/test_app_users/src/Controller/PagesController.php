<?php
declare(strict_types=1);

namespace UsersTestApp\Controller;

use Cake\Controller\Controller;
use Cake\Http\Response;

/**
 * A protected API route that answers with the identity of the request.
 */
class PagesController extends Controller
{
    /**
     * @return \Cake\Http\Response
     */
    public function me(): Response
    {
        $identity = $this->request->getAttribute('identity');
        if ($identity === null) {
            return $this->response
                ->withStatus(401)
                ->withType('application/json')
                ->withStringBody('{"error":"unauthorized"}');
        }

        return $this->response
            ->withType('application/json')
            ->withStringBody((string)json_encode(['id' => $identity->getIdentifier()]));
    }
}
