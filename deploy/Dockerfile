# The KiwiCaptcha reference deployment image: the PHP core with the
# fixture/quick-start server (the same /challenge + /verify semantics
# the bundle controller exposes, backed by the core storage). The
# production Symfony deployment is the published bundle + recipe; this
# image is the self-contained stand-in that keeps the exact security
# semantics of the library integration.
FROM php:8.4-cli-alpine
RUN apk add --no-cache git unzip \
 && docker-php-ext-install -j"$(nproc)" bcmath \
 && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
WORKDIR /srv/kiwicaptcha
COPY packages/kiwicaptcha-php/composer.json packages/kiwicaptcha-php/composer.lock ./composer.json ./composer.lock
COPY packages/kiwicaptcha-php/src ./src
COPY tests/browser/router.php ./router.php
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist --no-scripts --optimize-autoloader \
 && cp -r vendor ./vendor \
 && cp packages/kiwicaptcha-php/vendor ./vendor 2>/dev/null || true
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD php -r 'exit(@file_get_contents("http://127.0.0.1:8080/healthz") !== false ? 0 : 1);'
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/srv/kiwicaptcha", "/srv/kiwicaptcha/router.php"]
