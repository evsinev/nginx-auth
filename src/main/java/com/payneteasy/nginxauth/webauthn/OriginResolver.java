package com.payneteasy.nginxauth.webauthn;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;
import java.util.Optional;

/**
 * Resolves the origin of the host being served from the Host header and the configured allowlist,
 * and checks the browser Origin header against it.
 */
public final class OriginResolver {

    private final List<AllowedOrigin> origins;

    public OriginResolver(List<AllowedOrigin> aOrigins) {
        origins = List.copyOf(aOrigins);
    }

    public Optional<String> resolve(String aHostHeader) {
        for (AllowedOrigin origin : origins) {
            if (origin.matchesHostHeader(aHostHeader)) {
                return Optional.of(origin.getOrigin());
            }
        }
        return Optional.empty();
    }

    public Optional<String> resolve(HttpServletRequest aRequest) {
        return resolve(aRequest.getHeader("Host"));
    }

    /**
     * Origin of a browser POST: the Host must be in the allowlist and the Origin header must equal it exactly.
     */
    public Optional<String> checkPost(HttpServletRequest aRequest) {
        Optional<String> expected = resolve(aRequest);
        String actual = aRequest.getHeader("Origin");
        if (expected.isPresent() && expected.get().equals(actual)) {
            return expected;
        }
        return Optional.empty();
    }
}
