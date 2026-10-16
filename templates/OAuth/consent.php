<?php
/**
 * @var \Cake\View\View $this
 * @var \CakeDC\OAuth\Server\View\ConsentView $consent
 */

use CakeDC\OAuth\Server\Client\ClientType;

// A client described by a metadata document names itself; the host of its client_id URL is what can
// be trusted, so that is what the headline and the title show.
$clientHost = $consent->clientHost();
$clientName = $consent->client->type === ClientType::MetadataDocument && $clientHost !== ''
    ? $clientHost
    : $consent->client->name;
$this->assign('title', __d('oauth_server', 'Authorize {0}', $clientName));
?>
<h1><?= h(__d('oauth_server', '{0} wants to access {1}', $clientName, $consent->resource->name)) ?></h1>
<p class="oauth-muted"><?= h(__d(
    'oauth_server',
    'The request comes from {0}. Your answer is sent to {1}.',
    $clientHost !== '' ? $clientHost : $consent->redirectHost(),
    $consent->redirectHost(),
)) ?></p>
<?php if ($consent->isUnverified()) : ?>
    <p class="oauth-warning"><?= h(__d(
        'oauth_server',
        'This application registered itself; its name is not verified.',
    )) ?></p>
<?php endif; ?>
<?php if ($consent->isLoopbackOnly()) : ?>
    <p class="oauth-warning"><?= h(__d(
        'oauth_server',
        'Only continue if you just started this from an application on this computer: '
        . 'any program on this computer can use this address.',
    )) ?></p>
<?php endif; ?>
<p><?= h(__d('oauth_server', 'Signed in as {0}.', $consent->owner->displayName)) ?></p>
<p><?= h(__d('oauth_server', 'It will be able to:')) ?></p>
<ul>
    <?php foreach ($consent->scopes as $description) : ?>
        <li><?= h(__((string)$description)) ?></li>
    <?php endforeach; ?>
    <?php if ($consent->offlineAccess) : ?>
        <li><?= h(__d('oauth_server', 'Stay connected until you revoke it.')) ?></li>
    <?php endif; ?>
</ul>
<?= $this->Form->create(null, ['url' => $consent->formAction]) ?>
<?php foreach ($consent->fields as $name => $value) : ?>
    <input type="hidden" name="<?= h((string)$name) ?>" value="<?= h((string)$value) ?>">
<?php endforeach; ?>
<?= $this->Form->button(__d('oauth_server', 'Allow'), ['name' => 'decision', 'value' => 'approve']) ?>
<?= $this->Form->button(__d('oauth_server', 'Deny'), [
    'name' => 'decision',
    'value' => 'deny',
    'class' => 'oauth-secondary',
]) ?>
<?= $this->Form->end() ?>
