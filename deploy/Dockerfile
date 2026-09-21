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
#
# The base tag stays pinned to php:8.4-cli-alpine; digest-pinning the
# base image is the release posture and belongs to the deployment
# that publishes the image (a digest is recorded at release time from
# the exact image the release pipeline built against, never invented
# here).
FROM php:8.4-cli-alpine

# The sha384 of https://getcomposer.org/installer, pinned in the build
# argument and verified before the installer runs; bump the value in
# lockstep with composer releases (the published hash of the current
# installer, from https://getcomposer.org/download/).
ARG COMPOSER_INSTALLER_SHA384=c8b085408188070d5f52bcfe4ecfbee5f727afa458b2573b8eaaf77b3419b0bf2768dc67c86944da1544f06fa544fd47

RUN apk add --no-cache git unzip gmp-dev curl \
 && docker-php-ext-install -j"$(nproc)" bcmath gmp \
 && curl -fsSL -o /tmp/composer-setup.php https://getcomposer.org/installer \
 && php -r 'if (hash_file("sha384", "/tmp/composer-setup.php") !== $argv[1]) { fwrite(STDERR, "composer installer sha384 mismatch\n"); exit(1); }' "$COMPOSER_INSTALLER_SHA384" \
 && php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer \
 && rm /tmp/composer-setup.php

WORKDIR /srv/kiwicaptcha
# The lock file rides the build: the vendor tree is installed from the
# audited lock, so the shipped vendor is exactly the locked dependency
# set. Only the composer manifests and the core sources precede the
# install; the app files land after it, and vendor/ is never
# overwritten by a later copy.
COPY deploy/app/composer.json deploy/app/composer.lock deploy/app/
COPY packages/kiwicaptcha-php/composer.json packages/kiwicaptcha-php/composer.json
COPY packages/kiwicaptcha-php/src packages/kiwicaptcha-php/src
WORKDIR /srv/kiwicaptcha/deploy/app
# The vendor tree installs exactly from the copied lock: composer
# validate confirms the lock is in sync with the manifest, and
# composer install from a lock refuses an out-of-sync state, so the
# shipped vendor is the audited locked dependency set.
RUN composer validate --strict \
 && composer install --no-interaction --no-progress --prefer-dist --no-dev --optimize-autoloader
# The app files land after the install (the working directory), so
# vendor/ is never overwritten by a later copy.
COPY deploy/app/bootstrap.php deploy/app/health.php deploy/app/router.php deploy/app/solve.php ./

# The serving runtime is unprivileged: the app writes nothing under
# /srv, so it runs as a dedicated non-root user owning the tree.
RUN addgroup -S kiwi && adduser -S -G kiwi -H -h /srv/kiwicaptcha kiwi \
 && chown -R kiwi:kiwi /srv/kiwicaptcha
USER kiwi

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
