<?php
declare(strict_types=1);

namespace TestApp\Controller;

use Cake\Controller\Controller;
use Cake\Core\Configure;

/**
 * Base controller of the test application.
 */
class AppController extends Controller
{
    /**
     * @return void
     */
    public function initialize(): void
    {
        parent::initialize();
        $this->loadComponent('Authentication.Authentication', [
            'requireIdentity' => false,
            'identityAttribute' => Configure::read('TestApp.identityAttribute', 'identity'),
        ]);
        $this->loadComponent('Authorization.Authorization');
    }
}
