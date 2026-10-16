<?php
/**
 * @var \Cake\View\View $this
 * @var \CakeDC\OAuth\Server\Exception\OAuthException $error
 * @var \CakeDC\OAuth\Server\View\RedirectNoticeView|null $notice Set when the failed request could go back to a
 *   client the server does not trust: name the destination and offer the link, never follow it (no script, no meta
 *   refresh).
 */
$this->assign('title', h(__d('oauth_server', 'Authorization failed')));
?>
<h1><?= h(__d('oauth_server', 'Authorization failed')) ?></h1>
<p><?= h(__d('oauth_server', 'The application sent a request that cannot be completed.')) ?></p>
<p><?= h($error->getMessage()) ?></p>
<p class="oauth-muted"><code><?= h($error->error) ?></code></p>
<?php if (($notice ?? null) !== null) : ?>
    <?php
    $host = $notice->redirectHost();
    $continue = __d('oauth_server', 'Continue to {0}', $host);
    ?>
    <p class="oauth-warning"><?= h(__d(
        'oauth_server',
        'The application asked to send this answer to {0}. This server cannot confirm that {0} belongs to it: '
        . 'only continue if you trust it.',
        $host,
    )) ?></p>
    <?php // A plain link: the router would not leave a private-use scheme alone. ?>
    <p><a href="<?= h($notice->continueUrl) ?>" rel="noreferrer"><?= h($continue) ?></a></p>
<?php endif; ?>
