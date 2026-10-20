<?php

declare(strict_types=1);

namespace BelConsulting\KiwiCaptchaBundle\Http;

use Symfony\Component\HttpFoundation\Request;

/**
 * The universal HTTP framing rule shared by every security-sensitive
 * endpoint (challenge, cancellation, SiteVerify): one canonical HTTP
 * representation.
 *
 *   Content-Length:        max one occurrence, canonical decimal grammar.
 *   Transfer-Encoding:     max one occurrence, 'chunked' only, never
 *                          together with Content-Length.
 *   Content-Type:          max one occurrence.
 *   Content-Encoding:      max one occurrence.
 *   Host:                  max one occurrence, no controls or spaces.
 *
 * A duplicated header (two different values) is the kind of ambiguity
 * different proxies and application layers interpret differently, so it
 * is refused rather than silently collapsed.
 *
 * SAPI caveat: duplicate-header detection only fires where the SAPI
 * preserves duplicate occurrences as separate values in the request
 * bag. Conventional php-fpm/nginx typically collapse duplicates into
 * one comma-joined value before PHP sees them. Under that stack the
 * duplicate rows of this contract are therefore enforced by the
 * intermediary's own collapse (a single non-canonical value is still
 * refused by the grammar checks). The full duplicate-refusal behavior is
 * effective
 * under FrankenPHP, Swoole, and the test harness (built Symfony
 * Requests), where every occurrence reaches the application verbatim.
 */
trait FramingChecksTrait
{
    /**
     * Whether the raw request target is the canonical origin-form path.
     * False means the caller must refuse the request before any handling.
     * The caller builds its own response vocabulary.
     *
     * The raw target is inspected, never a normalized route. An
     * intermediary that rewrites or normalizes the target (a matrix
     * parameter, a trailing dot, a fragment, an absolute-form scheme and
     * host, or a dot segment) would otherwise let a second spelling of
     * the target reach the endpoint's state-changing pipeline.
     *
     * Rejected shapes:
     *  - anything without a leading slash: absolute-form, authority-form
     *    and relative targets.
     *  - a fragment ("#") anywhere in the target.
     *  - any byte outside printable ASCII: raw spaces, tabs, CR, LF,
     *    NUL, DEL, other control bytes and non-ASCII bytes.
     *  - any percent-encoded byte, backslash or matrix semicolon in the
     *    path.
     *  - any empty or dot segment ("//", a trailing slash, "/.", "/..").
     *  - any segment ending with "." (some intermediaries strip the dot
     *    and fold "/challenge." onto "/challenge").
     *
     * Only the path component is inspected here; a query string is
     * rejected separately by each endpoint.
     */
    private function isCanonicalRequestTarget(string $rawRequestUri): bool
    {
        if ($rawRequestUri === '' || $rawRequestUri[0] !== '/') {
            return false;
        }
        if (str_contains($rawRequestUri, '#') || preg_match('/[^\x21-\x7E]/', $rawRequestUri) === 1) {
            return false;
        }
        $path = $rawRequestUri;
        $queryPos = strpos($rawRequestUri, '?');
        if ($queryPos !== false) {
            $path = substr($rawRequestUri, 0, $queryPos);
        }
        if (str_contains($path, '%') || str_contains($path, '\\') || str_contains($path, ';')) {
            return false;
        }
        // RFC 3986 pchar only: an intermediary that is stricter than this
        // endpoint must never see a second spelling it would reject or
        // normalize. The rejected set includes pipe, angle brackets,
        // quotes, braces, caret, backtick and square brackets.
        if (preg_match('/[^A-Za-z0-9._~!$&\'()*+,=:@\/-]/', $path) === 1) {
            return false;
        }
        // The empty element before the leading slash is the absolute-path
        // marker, not a segment (guaranteed present by the check above);
        // every other empty segment (a `//` in the middle, or the trailing
        // `/` of "/challenge/") is noncanonical.
        $segments = explode('/', $path);
        for ($i = 1, $count = \count($segments); $i < $count; $i++) {
            $segment = $segments[$i];
            if ($segment === '' || $segment === '.' || $segment === '..') {
                return false;
            }
            if ($segment[\strlen($segment) - 1] === '.') {
                return false;
            }
        }

        return true;
    }

    /**
     * The ambiguity in the request's method-override input, or null when
     * the input is unambiguous.
     *
     * Symfony reads `X-HTTP-Method-Override` (and, when enabled, the
     * `_method` form field) in Request::getMethod() before routing and
     * the controller run. A duplicated header, a comma-joined or folded
     * value, or a header plus a form field lets the routing layer pick
     * an effective method the framing gate never examined. The early
     * request subscriber and the controllers both consult this rule.
     */
    private function methodOverrideConflict(Request $request): ?string
    {
        $values = $request->headers->all('x-http-method-override');
        if (\count($values) > 1) {
            return 'The X-HTTP-Method-Override header must appear at most once.';
        }
        $headerValue = $values[0] ?? null;
        if (!\is_string($headerValue)) {
            $headerValue = null;
        }
        // A comma is the collapsed-duplicate marker; CR or LF is an
        // obsolete fold. Both are second occurrences of a header the
        // contract requires to be singular, so neither reaches the
        // framework's method parser.
        if ($headerValue !== null
            && (str_contains($headerValue, ',') || str_contains($headerValue, "\r") || str_contains($headerValue, "\n"))
        ) {
            return 'The X-HTTP-Method-Override header must carry a single method value.';
        }
        if ($headerValue !== null && trim($headerValue) !== '' && $this->hasFormMethodOverride($request)) {
            return 'The request carries both an X-HTTP-Method-Override header and a _method form field.';
        }

        return null;
    }

    /**
     * Whether the query string carries a `_method` override. Request::
     * getMethod() honors it the moment anything asks for the effective
     * method, so the framing gate inspects the raw query bag before
     * routing does.
     */
    private function hasQueryMethodOverride(Request $request): bool
    {
        return $request->query->has('_method');
    }

    /**
     * Whether a form body carries a `_method` override. A framework-built
     * request already parsed the form body into the request bag, so the
     * bag is authoritative. A request built without that parse is scanned
     * as bounded URL-encoded bytes. A JSON body never counts.
     */
    private function hasFormMethodOverride(Request $request): bool
    {
        if ($request->request->has('_method')) {
            return true;
        }
        $contentType = strtolower(trim(explode(';', (string) $request->headers->get('Content-Type', ''), 2)[0]));
        if ($contentType !== 'application/x-www-form-urlencoded') {
            return false;
        }
        $stream = $request->getContent(true);
        if (!\is_resource($stream)) {
            return false;
        }
        $raw = (string) stream_get_contents($stream, 65536);
        if ($raw === '') {
            return false;
        }
        parse_str($raw, $parsed);

        return \array_key_exists('_method', $parsed);
    }

    /**
     * Whether the request's framing headers are canonical. False means
     * the caller must refuse the request (the caller builds its own
     * response vocabulary).
     */
    private function framingHeadersAcceptable(Request $request): bool
    {
        $lengths = $request->headers->all('Content-Length');
        if (\count($lengths) > 1) {
            return false;
        }
        // Canonical Content-Length grammar: a single canonical decimal
        // integer (0 or a leading-digit-non-zero sequence) — malformed
        // values (-1, +123, 123junk, "123, 123", empty) are refused
        // explicitly rather than left to PHP coercion, because this
        // repository deliberately defends across parser boundaries.
        if ($lengths !== []) {
            $value = $lengths[0];
            if (!\is_string($value)
                || $value === ''
                || preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) !== 1
            ) {
                return false;
            }
        }
        $transferEncodings = $request->headers->all('Transfer-Encoding');
        // Transfer-Encoding must be singular AND, if it survives at the
        // application boundary at all, the only representation a
        // de-chunking server stack can present is a single 'chunked'.
        if (\count($transferEncodings) > 1) {
            return false;
        }
        if ($lengths !== [] && $transferEncodings !== []) {
            return false;
        }
        if ($transferEncodings !== []) {
            $value = $transferEncodings[0];
            if (!\is_string($value) || strtolower(trim($value)) !== 'chunked') {
                return false;
            }
        }
        if (\count($request->headers->all('Content-Type')) > 1) {
            return false;
        }
        if (\count($request->headers->all('Content-Encoding')) > 1) {
            return false;
        }
        // The Host header is the routing identity every intermediary
        // reads. A duplicate or a value carrying whitespace/controls is
        // parser ambiguity, refused before any header-derived identity
        // is trusted.
        $hosts = $request->headers->all('host');
        if (\count($hosts) > 1) {
            return false;
        }
        if ($hosts !== []) {
            $host = $hosts[0];
            if (!\is_string($host) || $host === '' || preg_match('/[\x00-\x20\x7F,]/', $host) === 1) {
                return false;
            }
        }

        return true;
    }
}
