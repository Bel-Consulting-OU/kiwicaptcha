package com.kiwicaptcha.spring;

import com.kiwicaptcha.Decision;
import com.kiwicaptcha.servlet.KiwiCaptchaFilter;
import com.kiwicaptcha.servlet.TokenSourceResolver;
import com.kiwicaptcha.VerifyOutcome;
import com.kiwicaptcha.Verifier;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * The Spring MVC adapter: verifies at handler-mapping time and stores
 * the decision as a request attribute. Controllers read it under
 * KiwiCaptchaFilter.DECISION_ATTRIBUTE. Token authority follows the
 * shared rule the servlet filter applies: the x-kiwi-token header, the
 * kiwi_token form field and the kiwi_token query parameter must agree,
 * and distinct values refuse with token_source_conflict.
 */
public final class KiwiTokenInterceptor implements HandlerInterceptor {
    private final Verifier verifier;
    private final String secretKey;
    private final String expectedScope;
    private final java.util.List<String> trustedProxies;

    /** Builds the interceptor over the shared verifier. */
    public KiwiTokenInterceptor(Verifier verifier, String secretKey, String expectedScope,
                                java.util.List<String> trustedProxies) {
        this.verifier = verifier;
        this.secretKey = secretKey;
        this.expectedScope = expectedScope == null ? "" : expectedScope;
        this.trustedProxies = trustedProxies == null ? java.util.List.of() : trustedProxies;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        TokenSourceResolver.Result resolution = TokenSourceResolver.resolve(request);
        if (!resolution.ok()) {
            renderDenial(response,
                    Decision.fromOutcome(VerifyOutcome.invalid(resolution.error), ""));
            return false;
        }
        String token = resolution.token;
        Verifier.Options options = new Verifier.Options();
        options.secretKey = secretKey;
        options.expectedScope = expectedScope;
        options.clientIp = KiwiCaptchaFilter.clientIpFromRequest(request, trustedProxies);
        Decision decision = Decision.fromOutcome(verifier.verify(token, options), "");
        if (decision.ok) {
            request.setAttribute(KiwiCaptchaFilter.DECISION_ATTRIBUTE, decision);
            return true;
        }
        renderDenial(response, decision);
        return false;
    }

    private static void renderDenial(HttpServletResponse response, Decision decision) throws java.io.IOException {
        response.setStatus(decision.disposition.equals(Decision.DISPOSITION_RETRY) ? 503 : 403);
        response.setContentType("application/json");
        response.getWriter().write("{\"ok\":false,\"error\":\"" + decision.error
                + "\",\"disposition\":\"" + decision.disposition + "\"}");
    }
}
