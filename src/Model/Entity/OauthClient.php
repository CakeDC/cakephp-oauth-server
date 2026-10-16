<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Model\Entity;

use Cake\ORM\Entity;

/**
 * An OAuth client row. The core's storage contract decides what is written, and OrmStorage writes with explicit
 * `accessibleFields`, so no field is mass assignable: a form patched into it (an admin screen) changes nothing
 * unless the application lists the fields it means. The `secret_hash` is never serialized (toArray(), JSON).
 */
class OauthClient extends Entity
{
    /**
     * @var array<string, bool>
     */
    protected array $_accessible = ['*' => false];

    /**
     * @var list<string>
     */
    protected array $_hidden = ['secret_hash'];
}
