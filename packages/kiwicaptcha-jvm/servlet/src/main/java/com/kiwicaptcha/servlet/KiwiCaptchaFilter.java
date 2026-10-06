package com.kiwicaptcha.servlet;

import com.kiwicaptcha.Decision;
import com.kiwicaptcha.VerifyOutcome;
import com.kiwicaptcha.Verifier;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Framework middleware for the Jakarta Servlet stack: one auto-verify
 * filter the Spring Boot starter registers.
 *
 * The contract: a request carrying a valid, unconsumed token
 * proceeds; anything else is answered with a 403 Forbidden carrying
 * the machine-readable error code, and a retry disposition (a storage
 * outage or capacity exhaustion) answers with a 503 Service
 * Unavailable. The token source order is the x-kiwi-token header,
 * then the kiwi_token form field, then the kiwi_token query
 * parameter. The verified decision rides the request attribute
 * {@link #DECISION_ATTRIBUTE} for the wrapped handler.
 */
public class KiwiCaptchaFilter implements Filter {
    /** Token source header of the shared order. */
    public static final String TOKEN_HEADER = "X-Kiwi-Token";
    /** Token source field of the shared order. */
    public static final String TOKEN_FIELD = "kiwi_token";
    /** The request attribute the verified decision is stored under. */
    public static final String DECISION_ATTRIBUTE = "com.kiwicaptcha.decision";

    private final Verifier verifier;
    private final String secretKey;
    private final String expectedScope;
    private final PathPredicate pathPredicate;
    private final java.util.List<String> trustedProxies;
    private final DeniedRenderer denied;

    /** Answers whether the route, named by its path, needs a token. */
    public interface PathPredicate {
        boolean requiresToken(String path);
    }

    /** Overrides the default denial renderer when set. */
    public interface DeniedRenderer {
        void render(HttpServletRequest request, HttpServletResponse response, Decision decision)
                throws IOException;
    }

    /** Builds the filter over a verifier and the middleware options. */
    public KiwiCaptchaFilter(Verifier verifier, String secretKey, String expectedScope,
                             PathPredicate pathPredicate, java.util.List<String> trustedProxies,
                             DeniedRenderer denied) {
        this.verifier = verifier;
        this.secretKey = secretKey;
        // The scope is a required constructor parameter: a null scope
        // is a wiring error at construction, an empty one answers the
        // verifier's typed required_scope refusal at verify time.
        this.expectedScope = java.util.Objects.requireNonNull(expectedScope, "expectedScope is required");
        this.pathPredicate = pathPredicate;
        this.trustedProxies = trustedProxies == null ? java.util.List.of() : trustedProxies;
        this.denied = denied;
    }

    /** Builds the filter with the default denial renderer and no path predicate. */
    public KiwiCaptchaFilter(Verifier verifier, String secretKey, String expectedScope) {
        this(verifier, secretKey, expectedScope, null, java.util.List.of(), null);
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // Stateless: the verifier carries the deployment state.
    }

    @Override
    public void doFilter(ServletRequest rawRequest, ServletResponse rawResponse, FilterChain chain)
            throws IOException, ServletException {
        if (!(rawRequest instanceof HttpServletRequest request)
                || !(rawResponse instanceof HttpServletResponse response)) {
            chain.doFilter(rawRequest, rawResponse);
            return;
        }
        // Run once per request: a chained filter application must not
        // verify the same token twice.
        if (request.getAttribute(DECISION_ATTRIBUTE) != null) {
            chain.doFilter(rawRequest, rawResponse);
            return;
        }
        String pathScope = request.getRequestURI().replaceAll("^/+|/+$", "");
        if (pathScope.isEmpty()) {
            pathScope = "default";
        }
        if (pathPredicate != null && !pathPredicate.requiresToken(pathScope)) {
            chain.doFilter(rawRequest, rawResponse);
            return;
        }
        HttpServletRequest effective = request;
        String token = request.getHeader(TOKEN_HEADER);
        if (token == null || token.isEmpty()) {
            Map<String, String> form = parseForm(effective);
            token = form.get(TOKEN_FIELD);
            if (token == null || token.isEmpty()) {
                token = request.getParameter(TOKEN_FIELD);
            } else {
                effective = new FormParsedRequest(request, form);
            }
        }
        if (token == null || token.isEmpty()) {
            renderDenial(request, response,
                    Decision.fromOutcome(VerifyOutcome.malformedToken(SolutionTokenCode.MALFORMED), ""));
            return;
        }
        VerifyOutcome outcome = verifier.verify(token, options(request));
        Decision decision = Decision.fromOutcome(outcome, "");
        if (decision.ok) {
            request.setAttribute(DECISION_ATTRIBUTE, decision);
            chain.doFilter(effective, rawResponse);
            return;
        }
        renderDenial(request, response, decision);
    }

    private Verifier.Options options(HttpServletRequest request) {
        Verifier.Options options = new Verifier.Options();
        options.secretKey = secretKey;
        options.expectedScope = expectedScope;
        options.clientIp = clientIpFromRequest(request, trustedProxies);
        return options;
    }

    private void renderDenial(HttpServletRequest request, HttpServletResponse response, Decision decision)
            throws IOException {
        if (denied != null) {
            denied.render(request, response, decision);
            return;
        }
        response.setStatus(decision.disposition.equals(Decision.DISPOSITION_RETRY) ? 503 : 403);
        response.setContentType("application/json");
        response.getWriter().write("{\"ok\":false,\"error\":\"" + decision.error
                + "\",\"disposition\":\"" + decision.disposition + "\"}");
    }

    /**
     * Resolves the canonical client IP of a request against the
     * trusted-proxy CIDR list. An empty list (the default) trusts
     * nobody: forwarding headers are ignored and the socket peer is
     * the answer, so a client-supplied X-Forwarded-For can never move
     * the binding. The shared resolver in {@link ClientIpResolver}
     * owns the walk; this wrapper only lifts the servlet view (the
     * peer, every X-Forwarded-For line, the X-Real-IP value) into it.
     */
    public static String clientIpFromRequest(HttpServletRequest request, java.util.List<String> trustedProxies) {
        String peer = remotePeerText(request);
        java.util.List<String> xffLines = java.util.Collections.list(request.getHeaders("X-Forwarded-For"));
        String realIp = firstHeaderValue(request, "X-Real-IP");
        if ((xffLines == null || xffLines.isEmpty())
                && (realIp == null || realIp.isEmpty())) {
            // No forwarding signal anywhere: skip the resolver and
            // answer the peer directly, preserving the legacy shape.
            return peer;
        }
        return ClientIpResolver.resolve(peer, xffLines, realIp, trustedProxies);
    }

    private static String firstHeaderValue(HttpServletRequest request, String name) {
        java.util.Enumeration<String> values = request.getHeaders(name);
        if (values != null && values.hasMoreElements()) {
            return values.nextElement();
        }
        return null;
    }

    private static String remotePeerText(HttpServletRequest request) {
        String remote = request.getRemoteAddr();
        if (remote == null) {
            return "";
        }
        int colon = remote.lastIndexOf(':');
        // A bare ipv6 literal carries colons but no port; only strip a
        // port suffix when the host part is one unbracketed ipv4.
        if (colon > 0 && remote.indexOf(':') == colon && remote.indexOf('.') >= 0) {
            return remote.substring(0, colon);
        }
        return remote.replaceFirst("^\\[", "").replaceFirst("\\]$", "");
    }

    private static Map<String, String> parseForm(HttpServletRequest request) {
        String contentType = request.getContentType();
        Map<String, String> form = new HashMap<>();
        if (contentType == null || !contentType.contains("application/x-www-form-urlencoded")
                || !(request.getMethod().equals("POST") || request.getMethod().equals("PUT"))) {
            return form;
        }
        try {
            if (!(request.getCharacterEncoding() == null)) {
                // The container may already have consumed the stream.
            }
        } catch (RuntimeException ignored) {
            // The encoding probe never blocks the parse.
        }
        StringBuilder body = new StringBuilder();
        try (BufferedReader reader = request.getReader()) {
            int c;
            while ((c = reader.read()) >= 0) {
                body.append((char) c);
            }
        } catch (IOException | IllegalStateException e) {
            // A bad body leaves the field empty, never a thrown 500.
            return form;
        }
        for (String pair : body.toString().split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) {
                continue;
            }
            form.put(java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return form;
    }

    /** Malformed-token decode reason constant, shared with the core. */
    static final class SolutionTokenCode {
        static final String MALFORMED = "malformed";
    }

    /** Wraps the request so a pre-parsed form wins over re-reading the stream. */
    private static final class FormParsedRequest extends HttpServletRequestWrapper {
        private final Map<String, String> form;

        FormParsedRequest(HttpServletRequest delegate, Map<String, String> form) {
            super(delegate);
            this.form = form;
        }

        @Override
        public String getParameter(String name) {
            String value = form.get(name);
            return value != null ? value : super.getParameter(name);
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> merged = new HashMap<>(super.getParameterMap());
            for (Map.Entry<String, String> entry : form.entrySet()) {
                merged.put(entry.getKey(), new String[]{entry.getValue()});
            }
            return merged;
        }

        @Override
        public ServletInputStream getInputStream() {
            byte[] bytes = encodeForm().getBytes(StandardCharsets.UTF_8);
            ByteArrayInputStream backing = new ByteArrayInputStream(bytes);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return backing.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener listener) {
                    // Synchronous parse only.
                }

                @Override
                public int read() {
                    return backing.read();
                }
            };
        }

        private String encodeForm() {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> entry : form.entrySet()) {
                if (sb.length() > 0) {
                    sb.append('&');
                }
                sb.append(java.net.URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                        .append('=')
                        .append(java.net.URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
            }
            return sb.toString();
        }
    }
}
