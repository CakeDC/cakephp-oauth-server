<?php
/**
 * @var \Cake\View\View $this
 * @var \CakeDC\OAuth\Server\View\ConnectionsView $connections
 */

use CakeDC\OAuth\Server\Client\Client;
use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuthServer\View\QuotedName;

$this->assign('title', h(__d('oauth_server', 'Connected applications')));
$date = fn(?DateTimeInterface $value): string => $value === null
    ? __d('oauth_server', 'Never')
    : $value->format('Y-m-d H:i') . ' UTC';
// Hidden inputs are printed by hand: FormHelper does not escape the name attribute.
$hidden = fn(string $name, string $value): string => '<input type="hidden" name="' . h($name)
    . '" value="' . h($value) . '">';
$button = function (string $action, array $fields, string $label) use ($connections, $hidden): string {
    $html = $this->Form->create(null, ['url' => $connections->formAction]);
    $html .= $hidden('form_token', $connections->formToken);
    $html .= $hidden('action', $action);
    foreach ($fields as $name => $value) {
        $html .= $hidden((string)$name, (string)$value);
    }

    return $html . $this->Form->button($label, ['class' => 'oauth-secondary']) . $this->Form->end();
};
// The client cell. A metadata document client is named by its client_id host (its name is self-asserted). A
// self-registered client chose its name and its redirect URIs: the hosts of those lead (a fixed text for a private-use
// scheme), its name follows as a quote, and it is marked unverified.
$cell = function (Client $client): string {
    $host = $client->displayHost();
    if ($client->type === ClientType::MetadataDocument && $host !== '') {
        return h($host);
    }
    if ($client->type !== ClientType::Dynamic) {
        return h($client->name) . '<br><span class="oauth-muted">' . h($host) . '</span>';
    }
    $hosts = implode(', ', $client->webHosts());
    $html = h(match (true) {
        $hosts === '' => __d('oauth_server', 'An application on this computer'),
        $client->hasNonWebRedirect() => __d('oauth_server', '{0} and an application on this computer', $hosts),
        default => $hosts,
    });
    if ($client->name !== $hosts) {
        $html .= '<br><span class="oauth-muted">' . QuotedName::html(
            __d('oauth_server', 'It calls itself {0}. Anyone can choose that name.', QuotedName::PLACEHOLDER),
            $client->name,
        ) . '</span>';
    }

    return $html . '<br><span class="oauth-warning">'
        . h(__d('oauth_server', 'Unverified: this application registered itself.')) . '</span>';
};
?>
<h1><?= h(__d('oauth_server', 'Connected applications')) ?></h1>
<?php if ($connections->error !== null) : ?>
    <p class="oauth-warning"><?= h($connections->error) ?></p>
<?php endif; ?>
<?php if ($connections->connections === []) : ?>
    <p class="oauth-muted"><?= h(__d('oauth_server', 'No application is connected.')) ?></p>
<?php else : ?>
    <table>
        <tr>
            <th><?= h(__d('oauth_server', 'Application')) ?></th>
            <th><?= h(__d('oauth_server', 'Access to')) ?></th>
            <th><?= h(__d('oauth_server', 'Permissions')) ?></th>
            <th><?= h(__d('oauth_server', 'Connected')) ?></th>
            <th><?= h(__d('oauth_server', 'Last used')) ?></th>
            <th></th>
        </tr>
        <?php foreach ($connections->connections as $connection) : ?>
            <?php
            $revoke = $button(
                'revoke_connection',
                ['family_id' => $connection->familyId],
                __d('oauth_server', 'Revoke'),
            );
            ?>
            <tr>
                <td><?= $cell($connection->client) ?></td>
                <td><?= h($connections->resourceName($connection->resource)) ?></td>
                <td><?= h(implode(', ', $connection->scopes)) ?></td>
                <td><?= h($date($connection->connectedAt)) ?></td>
                <td><?= h($date($connection->lastUsedAt)) ?></td>
                <td><?= $revoke ?></td>
            </tr>
        <?php endforeach; ?>
    </table>
<?php endif; ?>
<?php if ($connections->personalTokensEnabled || $connections->personalTokens !== []) : ?>
    <h2><?= h(__d('oauth_server', 'Personal access tokens')) ?></h2>
    <?php if ($connections->newToken !== null) : ?>
        <p class="oauth-warning"><?= h(__d(
            'oauth_server',
            'Copy your new token now. It will not be shown again:',
        )) ?></p>
        <p><code><?= h($connections->newToken) ?></code></p>
    <?php endif; ?>
    <?php if ($connections->personalTokens === []) : ?>
        <p class="oauth-muted"><?= h(__d('oauth_server', 'You have no personal access tokens.')) ?></p>
    <?php else : ?>
        <table>
            <tr>
                <th><?= h(__d('oauth_server', 'Name')) ?></th>
                <th><?= h(__d('oauth_server', 'Resource')) ?></th>
                <th><?= h(__d('oauth_server', 'Permissions')) ?></th>
                <th><?= h(__d('oauth_server', 'Expires')) ?></th>
                <th></th>
            </tr>
            <?php foreach ($connections->personalTokens as $token) : ?>
                <tr>
                    <td><?= h((string)$token->name) ?></td>
                    <td><?= h($connections->resourceName($token->resource)) ?></td>
                    <td><?= h(implode(', ', $token->scopes)) ?></td>
                    <td><?= h($date($token->expiresAt)) ?></td>
                    <td><?= $button('revoke_token', ['token_id' => $token->id], __d('oauth_server', 'Revoke')) ?></td>
                </tr>
            <?php endforeach; ?>
        </table>
    <?php endif; ?>
    <?php if ($connections->creatable !== []) : ?>
        <?= $this->Form->create(null, ['url' => $connections->formAction]) ?>
        <?= $hidden('form_token', $connections->formToken) ?>
        <?= $hidden('action', 'create_token') ?>
        <?= $this->Form->control('name', [
            'label' => __d('oauth_server', 'Name'),
            'maxlength' => 100,
            'required' => true,
        ]) ?>
        <?= $this->Form->control('resource', [
            'label' => __d('oauth_server', 'Resource'),
            'options' => array_map(fn(array $resource): string => $resource['name'], $connections->creatable),
        ]) ?>
        <?php foreach ($connections->creatable as $resource) : ?>
            <fieldset>
                <legend><?= h($resource['name']) ?></legend>
                <?php foreach ($resource['scopes'] as $scope => $description) : ?>
                    <?php // Printed by hand: FormHelper would turn dots in scope names into brackets. ?>
                    <label>
                        <input type="checkbox" name="<?= h('scope:' . $scope) ?>" value="1">
                        <?= h(__((string)$description)) ?>
                    </label>
                <?php endforeach; ?>
            </fieldset>
        <?php endforeach; ?>
        <?= $this->Form->control('days', [
            'type' => 'number',
            'label' => __d('oauth_server', 'Expires in (days, up to {0})', $connections->maxDays),
            'min' => 1,
            'max' => $connections->maxDays,
            'value' => min(30, $connections->maxDays),
        ]) ?>
        <?= $this->Form->button(__d('oauth_server', 'Create token')) ?>
        <?= $this->Form->end() ?>
    <?php endif; ?>
<?php endif; ?>
