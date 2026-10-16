<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\View;

use Cake\Http\ServerRequest;
use CakeDC\OAuth\Server\Exception\OAuthException;
use CakeDC\OAuth\Server\View\ErrorPageRendererInterface;

/**
 * The error page as a Cake template (`templates/OAuth/error.php`).
 *
 * @internal
 */
final class CakeErrorPageRenderer implements ErrorPageRendererInterface
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
            ['error' => $error],
            $this->layout,
        );
    }
}
