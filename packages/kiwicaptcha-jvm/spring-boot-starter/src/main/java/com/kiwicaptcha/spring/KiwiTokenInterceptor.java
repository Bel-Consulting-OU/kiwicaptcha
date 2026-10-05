package com.kiwicaptcha.spring;

import com.kiwicaptcha.Decision;
import com.kiwicaptcha.servlet.KiwiCaptchaFilter;
import com.kiwicaptcha.VerifyOutcome;
import com.kiwicaptcha.Verifier;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * The Spring MVC adapter: verifies at handler-mapping time and stores
 * the decision as a request attribute. Controllers read it under
 * KiwiCaptchaFilter.DECISION_ATTRIBUTE. The token source order is the
 * x-kiwi-token header, then the kiwi_token form field, then the
 * query parameter, the same order the servlet filter applies.
 */
public final class KiwiTokenInterceptor implements HandlerInterceptor {
    private final Verifier verifier;
    private final String secretKey;
    private final String expectedScope;
    private final boolean realIp;

    /** Builds the interceptor over the shared verifier. */
    public KiwiTokenInterceptor(Verifier verifier, String secretKey, String expectedScope, boolean realIp) {
        this.verifier = verifier;
        this.secretKey = secretKey;
        this.expectedScope = expectedScope == null ? "" : expectedScope;
        this.realIp = realIp;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        String token = request.getHeader(KiwiCaptchaFilter.TOKEN_HEADER);
        if (token == null || token.isEmpty()) {
            token = request.getParameter(KiwiCaptchaFilter.TOKEN_FIELD);
        }
        if (token == null || token.isEmpty()) {
            renderDenial(response,
                    Decision.fromOutcome(VerifyOutcome.malformedToken("malformed"), ""));
            return false;
        }
        Verifier.Options options = new Verifier.Options();
        options.secretKey = secretKey;
        options.expectedScope = expectedScope;
        options.clientIp = KiwiCaptchaFilter.clientIpFromRequest(request, realIp);
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
