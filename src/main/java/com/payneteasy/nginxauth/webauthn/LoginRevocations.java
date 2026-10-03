package com.payneteasy.nginxauth.webauthn;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Revocation generation per login name (the typed name that selects the bind DN, case-insensitive).
 * A login request reads the generation before its LDAP bind and may publish a session or pre-auth only while
 * the generation is unchanged; a password change bumps it. Check and publication are atomic with the bump,
 * and a password change revokes sessions by login name after bumping, so a result published just before the
 * bump is revoked and one published after it is refused.
 */
public final class LoginRevocations {

    private static final class Generation {
        private long value;
    }

    private final ConcurrentHashMap<String, Generation> generations = new ConcurrentHashMap<>();

    /** Does not create entries, so unknown names typed at the login form cost no memory. */
    public long current(String aLoginName) {
        if (aLoginName == null) {
            return 0L;
        }
        Generation generation = generations.get(key(aLoginName));
        if (generation == null) {
            return 0L;
        }
        synchronized (generation) {
            return generation.value;
        }
    }

    public long bump(String aLoginName) {
        Generation generation = generations.computeIfAbsent(key(aLoginName), k -> new Generation());
        synchronized (generation) {
            return ++generation.value;
        }
    }

    /** Runs the publication only if the generation still equals the one read before the bind; else null. */
    public <T> T publishIf(String aLoginName, long aExpected, Supplier<T> aPublish) {
        if (aLoginName == null) {
            return aPublish.get();
        }
        Generation generation = generations.computeIfAbsent(key(aLoginName), k -> new Generation());
        synchronized (generation) {
            return generation.value == aExpected ? aPublish.get() : null;
        }
    }

    private static String key(String aLoginName) {
        return aLoginName.toLowerCase(Locale.ROOT);
    }
}
