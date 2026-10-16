<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\Model\Entity;

use Cake\ORM\Entity;

/**
 * An OAuth client row. The core's storage contract decides what is written; every field is accessible.
 */
class OauthClient extends Entity
{
    /**
     * @var array<string, bool>
     */
    protected array $_accessible = ['*' => true];
}
