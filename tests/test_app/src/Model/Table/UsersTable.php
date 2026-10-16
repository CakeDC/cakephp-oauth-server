<?php
declare(strict_types=1);

namespace TestApp\Model\Table;

use Cake\ORM\Query\SelectQuery;
use Cake\ORM\Table;

class UsersTable extends Table
{
    public function initialize(array $config): void
    {
        parent::initialize($config);
        $this->setDisplayField('name');
    }

    public function findActive(SelectQuery $query): SelectQuery
    {
        return $query->where([$this->aliasField('active') => true]);
    }
}
