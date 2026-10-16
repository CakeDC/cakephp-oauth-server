<?php
/**
 * @var \Cake\View\View $this
 * @var \CakeDC\OAuth\Server\Exception\OAuthException $error
 */
$this->assign('title', h(__d('oauth_server', 'Authorization failed')));
?>
<h1><?= h(__d('oauth_server', 'Authorization failed')) ?></h1>
<p><?= h(__d('oauth_server', 'The application sent a request that cannot be completed.')) ?></p>
<p><?= h($error->getMessage()) ?></p>
<p class="oauth-muted"><code><?= h($error->error) ?></code></p>
