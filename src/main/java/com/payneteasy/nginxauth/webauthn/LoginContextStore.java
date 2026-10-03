package com.payneteasy.nginxauth.webauthn;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Login contexts created by auth_request: carry the policyId and back URL of the protected location
 * to the login page through an opaque id.
 */
public final class LoginContextStore {

    public record LoginContext(String contextId, String policyId, String back, String origin, String browserBinding, long expiresAt) {
        LoginContext claimedBy(String aBinding) {
            return new LoginContext(contextId, policyId, back, origin, aBinding, expiresAt);
        }
    }

    private final long ttlMillis;
    private final int cap;
    private final LongSupplier clock;
    private final ConcurrentHashMap<String, LoginContext> contexts = new ConcurrentHashMap<>();

    public LoginContextStore(long aTtlMillis, int aCap, LongSupplier aClock) {
        ttlMillis = aTtlMillis;
        cap = aCap;
        clock = aClock;
    }

    /** Empty when the store is full. */
    public Optional<String> create(String aPolicyId, String aBack, String aOrigin) {
        long now = clock.getAsLong();
        if (contexts.size() >= cap) {
            contexts.values().removeIf(context -> context.expiresAt() <= now);
            if (contexts.size() >= cap) {
                return Optional.empty();
            }
        }
        String id = SecureTokens.random();
        contexts.put(id, new LoginContext(id, aPolicyId, aBack, aOrigin, null, now + ttlMillis));
        return Optional.of(id);
    }

    /**
     * Binds the context to the browser on first use. Later uses must come from the same binding and origin.
     */
    public Optional<LoginContext> claim(String aContextId, String aBinding, String aOrigin) {
        if (aContextId == null || aBinding == null || aOrigin == null) {
            return Optional.empty();
        }
        long now = clock.getAsLong();
        LoginContext[] result = new LoginContext[1];
        contexts.computeIfPresent(aContextId, (id, context) -> {
            if (context.expiresAt() <= now) {
                return null;
            }
            if (!aOrigin.equals(context.origin())) {
                return context;
            }
            if (context.browserBinding() == null) {
                result[0] = context.claimedBy(aBinding);
                return result[0];
            }
            if (context.browserBinding().equals(aBinding)) {
                result[0] = context;
            }
            return context;
        });
        return Optional.ofNullable(result[0]);
    }

    int size() {
        return contexts.size();
    }
}
