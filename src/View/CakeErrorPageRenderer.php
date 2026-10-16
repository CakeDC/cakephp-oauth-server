<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\View;

use Cake\Http\ServerRequest;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\View\ErrorPageRendererInterface;
use CakeDC\OAuth\Server\View\RedirectNoticeRendererInterface;
use CakeDC\OAuth\Server\View\RedirectNoticeView;

/**
 * The error page as a Cake template (`templates/OAuth/error.php`), also where the core shows it instead of sending a
 * failed request back to a client it does not trust: the template then gets `$notice`, names the destination and
 * links to it.
 *
 * @internal
 */
final class CakeErrorPageRenderer implements ErrorPageRendererInterface, RedirectNoticeRendererInterface
{
    /**
     * @param \Cake\Http\ServerRequest|null $request The current request.
     * @param string|false|null $layout Layout.
     */
    public function __construct(
        private readonly ?ServerRequest $request,
        private readonly string|false|null $layout,
    ) {
    }

    /**
     * @inheritDoc
     */
    public function render(OAuthException $error): string
    {
        return CakeTemplateRenderer::render(
            $this->request,
            'error',
            ['error' => $error, 'notice' => null],
            $this->layout,
        );
    }

    /**
     * @inheritDoc
     */
    public function renderRedirectNotice(RedirectNoticeView $view): string
    {
        return CakeTemplateRenderer::render(
            $this->request,
            'error',
            ['error' => $view->error, 'notice' => $view],
            $this->layout,
        );
    }
}
