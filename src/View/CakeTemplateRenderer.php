<?php
declare(strict_types=1);

namespace CakeDC\OAuthServer\View;

use Cake\Http\ServerRequest;
use Cake\Routing\Router;
use Cake\View\ViewBuilder;

/**
 * Renders the plugin's templates to strings for the core's page renderers.
 *
 * @internal
 */
final class CakeTemplateRenderer
{
    /**
     * Renders `templates/OAuth/<template>.php` with the app's view class (`AppView` when it has one).
     *
     * The router's URL context is the request's while rendering, so form actions carry the application's
     * base path (the core hands over app-relative paths).
     *
     * @param \Cake\Http\ServerRequest|null $request The current request; the router's otherwise.
     * @param string $template Template name.
     * @param array<string, mixed> $vars View variables.
     * @param string|false|null $layout A layout, false for none, null for the plugin's.
     * @return string
     */
    public static function render(
        ?ServerRequest $request,
        string $template,
        array $vars,
        string|false|null $layout,
    ): string {
        $routed = Router::getRequest();
        $request ??= $routed ?? new ServerRequest();
        if ($routed !== $request) {
            Router::setRequest($request);
        }

        try {
            $builder = new ViewBuilder();
            $builder->setPlugin('CakeDC/OAuthServer')
                ->setTemplatePath('OAuth')
                ->setTemplate($template)
                ->setVars($vars);
            if ($layout === false) {
                $builder->disableAutoLayout();
            } else {
                $builder->setLayout($layout ?? 'CakeDC/OAuthServer.oauth');
            }

            return $builder->build(request: $request)->render();
        } finally {
            if ($routed !== null && $routed !== $request) {
                Router::setRequest($routed);
            }
        }
    }
}
