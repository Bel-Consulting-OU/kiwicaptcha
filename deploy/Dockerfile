# The KiwiCaptcha reference deployment image: the PHP core behind a
# small php -S request surface (GET /healthz, POST /challenge,
# POST /verify), backed by the real core RedisStorage on Valkey/Redis.
# Configuration comes exclusively from environment variables; no fixed
# secret, test credential or trapdoor value is baked into the image.
# The production deployment surface is the published Symfony bundle;
# this image is the self-contained stand-in that exercises the exact
# core library code paths (issuer, verifier, atomic Redis storage).
#
# The layout mirrors the repository under /srv/kiwicaptcha so the
# deploy/app/composer.json path repository ("../../packages/
# kiwicaptcha-php") resolves the same way it does in a developer
# checkout.
FROM php:8.4-cli-alpine
RUN apk add --no-cache git unzip gmp-dev \
 && docker-php-ext-install -j"$(nproc)" bcmath gmp \
 && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
WORKDIR /srv/kiwicaptcha
COPY deploy/app/composer.json deploy/app/composer.json
COPY packages/kiwicaptcha-php/composer.json packages/kiwicaptcha-php/composer.json
COPY packages/kiwicaptcha-php/src packages/kiwicaptcha-php/src
WORKDIR /srv/kiwicaptcha/deploy/app
RUN composer install --no-interaction --no-progress --prefer-dist --no-dev --optimize-autoloader
COPY deploy/app deploy/app
EXPOSE 8080
# The healthcheck runs the real /healthz handler, which round-trips the
# configured challenge store (write, read, delete-if-pending) and
# answers 503 when the store is unreachable; the check requires the 200
# status, so a 503 body never counts as healthy.
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD php -r '$b=@file_get_contents("http://127.0.0.1:8080/healthz"); $h=$http_response_header[0] ?? ""; exit(str_starts_with($h, "HTTP/1.1 200") || str_starts_with($h, "HTTP/1.0 200") ? 0 : 1);'
# The router handles every request itself, so php -S never serves a
# static file and no app file is reachable by URL.
CMD ["php", "-S", "0.0.0.0:8080", "-t", "/srv/kiwicaptcha/deploy/app", "/srv/kiwicaptcha/deploy/app/router.php"]
