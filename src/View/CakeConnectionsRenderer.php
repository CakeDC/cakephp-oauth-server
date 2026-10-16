<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\View;

use Cake\Http\ServerRequest;
use CakeDC\OAuth\Server\View\ConnectionsRendererInterface;
use CakeDC\OAuth\Server\View\ConnectionsView;

/**
 * The connections page as a Cake template (`templates/OAuth/connections.php`).
 */
final class CakeConnectionsRenderer implements ConnectionsRendererInterface
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
    public function render(ConnectionsView $view): string
    {
        return CakeTemplateRenderer::render(
            $this->request,
            'connections',
            ['connections' => $view],
            $this->layout,
        );
    }
}
