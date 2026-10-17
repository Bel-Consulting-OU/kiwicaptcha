package com.kiwicaptcha.servlet;

import com.kiwicaptcha.VerifyError;

import jakarta.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The shared token authority rule of the server SDKs, pinned by
 * protocol/decision-v1/corpus.json.
 *
 * Every non-empty value is collected from all three sources (the
 * x-kiwi-token header, the kiwi_token form field, the kiwi_token query
 * parameter), repeated values included. One distinct value verifies,
 * however many sources carry it. Two or more distinct values refuse
 * the request with token_source_conflict before any candidate is
 * verified, so a trusted gateway's header can never be shadowed by an
 * attacker-controlled body field.
 */
public final class TokenSourceResolver {
    private TokenSourceResolver() {}

    /** The resolution result: one token or one typed failure. */
    public static final class Result {
        /** The agreed token, null on a failure. */
        public final String token;
        /** The typed failure, null on success. */
        public final VerifyError error;

        private Result(String token, VerifyError error) {
            this.token = token;
            this.error = error;
        }

        /** Whether one agreed token is available. */
        public boolean ok() {
            return error == null;
        }
    }

    /** Applies the rule to the collected source values. */
    public static Result resolveValues(List<String> headerValues, List<String> formValues,
                                       List<String> queryValues) {
        List<String> distinct = new ArrayList<>(1);
        List<String> headers = new ArrayList<>();
        for (String line : headerValues) {
            // A proxy may fold duplicate header lines into one comma
            // list. The token alphabet has no comma, so each entry is a
            // candidate.
            if (line == null) {
                continue;
            }
            for (String part : line.split(",")) {
                String value = part.trim();
                if (!value.isEmpty()) {
                    headers.add(value);
                }
            }
        }
        for (List<String> group : List.of(headers, formValues, queryValues)) {
            for (String value : group) {
                if (value == null || value.isEmpty() || distinct.contains(value)) {
                    continue;
                }
                distinct.add(value);
                if (distinct.size() > 1) {
                    return new Result(null, VerifyError.TOKEN_SOURCE_CONFLICT);
                }
            }
        }
        if (distinct.isEmpty()) {
            return new Result(null, VerifyError.MALFORMED_TOKEN);
        }
        return new Result(distinct.get(0), null);
    }

    /**
     * Resolves the token of one servlet request. The servlet container
     * exposes the form and query parameters together through
     * getParameterValues, which is exactly the union the rule needs;
     * repeated values are preserved by the container.
     */
    public static Result resolve(HttpServletRequest request) {
        List<String> headers = Collections.list(request.getHeaders(KiwiCaptchaFilter.TOKEN_HEADER));
        String[] parameterValues = request.getParameterValues(KiwiCaptchaFilter.TOKEN_FIELD);
        List<String> parameters = parameterValues == null ? List.of() : List.of(parameterValues);
        return resolveValues(headers, parameters, List.of());
    }
}
