<?php
declare(strict_types=1);

return [
    'CakeDC/Auth.permissions' => [
        ['role' => '*', 'controller' => 'Pages', 'action' => 'me', 'bypassAuth' => true],
        ['role' => 'user', 'plugin' => 'CakeDC/Users', 'controller' => 'Users', 'action' => '*'],
    ],
];
