<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\View;

use Cake\Http\ServerRequest;
use CakeDC\OAuth\Server\View\ConsentRendererInterface;
use CakeDC\OAuth\Server\View\ConsentView;

/**
 * The consent page as a Cake template (`templates/OAuth/consent.php`).
 */
final class CakeConsentRenderer implements ConsentRendererInterface
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
    public function render(ConsentView $view): string
    {
        return CakeTemplateRenderer::render(
            $this->request,
            'consent',
            ['consent' => $view],
            $this->layout,
        );
    }
}
