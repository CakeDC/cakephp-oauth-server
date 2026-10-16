<?php
/**
 * @var \Cake\View\View $this
 * @var \CakeDC\OAuth\Server\View\ConsentView $consent
 */

use CakeDC\OAuth\Server\Client\ClientType;
use CakeDC\OAuthServer\View\QuotedName;

// A name is chosen by the client, so the title and the heading use what it cannot choose freely
// (ConsentView::clientLabel(): a registered client's name, the client_id host of a metadata document, the host a
// self-registered client's answer goes to), or a fixed text when no host names it (a private-use redirect).
$label = $consent->clientLabel();
$client = $label !== '' ? $label : __d('oauth_server', 'An application on this computer');
$local = false;
$from = $consent->clientHost() !== '' ? $consent->clientHost() : $consent->redirectHost();
if ($consent->client->type === ClientType::Dynamic && $consent->clientHost() === '') {
    // The scheme of a private-use redirect is chosen by the client: it is shown only as the destination.
    $local = true;
}
// The name the client declared, as an unverified quote whose boundary is markup.
$declared = $consent->declaredName() === null ? null : QuotedName::html(
    __d('oauth_server', 'It calls itself {0}. Anyone can choose that name.', QuotedName::PLACEHOLDER),
    $consent->declaredName(),
);
$this->assign('title', h(__d('oauth_server', 'Authorize {0}', $client)));
?>
<h1><?= h(__d('oauth_server', '{0} wants to access {1}', $client, $consent->resource->name)) ?></h1>
<p class="oauth-muted"><?= h($local ? __d(
    'oauth_server',
    'The request comes from an application on this computer. Your answer is sent to {0}.',
    $consent->redirectHost(),
) : __d(
    'oauth_server',
    'The request comes from {0}. Your answer is sent to {1}.',
    $from,
    $consent->redirectHost(),
)) ?></p>
<?php if ($declared !== null) : ?>
    <p class="oauth-muted"><?= $declared ?></p>
<?php endif; ?>
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
<?php if ($consent->approvedBefore) : ?>
    <p class="oauth-warning"><?= h(__d(
        'oauth_server',
        'You approved this application before. It is asked again because its identity cannot be confirmed: '
        . 'only continue if you started this yourself.',
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
