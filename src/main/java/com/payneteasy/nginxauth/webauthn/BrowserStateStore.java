package com.payneteasy.nginxauth.webauthn;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.function.UnaryOperator;

/**
 * Server side of the browser binding cookie: CSRF synchronizer token and the pending pre-authentication.
 */
public final class BrowserStateStore {

    public static final String COOKIE_NAME = "AUTH_BINDING";

    public static final class BrowserState {
        private final String binding;
        private final String csrfToken;
        private volatile PreAuth preAuth;
        private volatile long lastSeen;
        private volatile long generation;

        private BrowserState(String binding, String csrfToken, long now) {
            this.binding = binding;
            this.csrfToken = csrfToken;
            this.lastSeen = now;
        }

        public String binding() {
            return binding;
        }

        public String csrfToken() {
            return csrfToken;
        }

        public PreAuth preAuth() {
            return preAuth;
        }

        /** Grows on every logout; a request that started before a logout must not publish anything. */
        public long generation() {
            return generation;
        }
    }

    private final long idleTtlMillis;
    private final int cap;
    private final LongSupplier clock;
    private final ConcurrentHashMap<String, BrowserState> states = new ConcurrentHashMap<>();

    public BrowserStateStore(long aIdleTtlMillis, int aCap, LongSupplier aClock) {
        idleTtlMillis = aIdleTtlMillis;
        cap = aCap;
        clock = aClock;
    }

    /**
     * Returns the state for a known binding or creates a new one. Empty when the store is full.
     */
    public Optional<BrowserState> getOrCreate(String aBinding) {
        Optional<BrowserState> existing = get(aBinding);
        if (existing.isPresent()) {
            return existing;
        }
        long now = clock.getAsLong();
        if (states.size() >= cap) {
            purgeExpired(now);
            if (states.size() >= cap) {
                return Optional.empty();
            }
        }
        BrowserState state = new BrowserState(SecureTokens.random(), SecureTokens.random(), now);
        states.put(state.binding, state);
        return Optional.of(state);
    }

    public Optional<BrowserState> get(String aBinding) {
        if (aBinding == null) {
            return Optional.empty();
        }
        BrowserState state = states.get(aBinding);
        if (state == null) {
            return Optional.empty();
        }
        long now = clock.getAsLong();
        if (now - state.lastSeen > idleTtlMillis) {
            states.remove(aBinding, state);
            return Optional.empty();
        }
        state.lastSeen = now;
        return Optional.of(state);
    }

    public boolean checkCsrf(BrowserState aState, String aToken) {
        return SecureTokens.constantTimeEquals(aState.csrfToken, aToken);
    }

    public void setPreAuth(BrowserState aState, PreAuth aPreAuth) {
        synchronized (aState) {
            aState.preAuth = aPreAuth;
        }
    }

    /** Replaces the pre-auth only if it is still the one with the given id. */
    public boolean updatePreAuth(BrowserState aState, String aPreauthId, UnaryOperator<PreAuth> aUpdate) {
        synchronized (aState) {
            PreAuth current = aState.preAuth;
            if (current == null || !current.preauthId().equals(aPreauthId)) {
                return false;
            }
            aState.preAuth = aUpdate.apply(current);
            return true;
        }
    }

    public void clearPreAuth(BrowserState aState, String aPreauthId) {
        synchronized (aState) {
            PreAuth current = aState.preAuth;
            if (current != null && (aPreauthId == null || current.preauthId().equals(aPreauthId))) {
                aState.preAuth = null;
            }
        }
    }

    /** Must be called holding the state monitor. */
    void nextGeneration(BrowserState aState) {
        aState.generation++;
    }

    public void clearPreAuthForUser(String aUid) {
        for (BrowserState state : states.values()) {
            synchronized (state) {
                PreAuth current = state.preAuth;
                if (current != null && current.uid().equals(aUid)) {
                    state.preAuth = null;
                }
            }
        }
    }

    int size() {
        return states.size();
    }

    private void purgeExpired(long aNow) {
        states.values().removeIf(state -> aNow - state.lastSeen > idleTtlMillis);
    }
}
