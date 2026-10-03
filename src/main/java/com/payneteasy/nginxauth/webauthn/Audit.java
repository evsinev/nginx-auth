package com.payneteasy.nginxauth.webauthn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Security audit log ({@code nginx-auth.audit}): {@code event=... key=value ...}.
 * Never pass key material, challenges, assertions, tokens, passwords or secrets; credential IDs go through
 * {@link #cred(String)}.
 */
public final class Audit {

    private static final Logger AUDIT = LoggerFactory.getLogger("nginx-auth.audit");

    private Audit() {
    }

    public static void log(String aEvent, String... aKeyValues) {
        if (!AUDIT.isInfoEnabled()) {
            return;
        }
        StringBuilder sb = new StringBuilder("event=").append(aEvent);
        for (int i = 0; i + 1 < aKeyValues.length; i += 2) {
            sb.append(' ').append(aKeyValues[i]).append('=').append(clean(aKeyValues[i + 1]));
        }
        AUDIT.info("{}", sb);
    }

    public static String cred(String aCredentialId) {
        return SecureTokens.shortHash(aCredentialId);
    }

    static String clean(String aValue) {
        if (aValue == null) {
            return "-";
        }
        StringBuilder sb = new StringBuilder(Math.min(aValue.length(), 256));
        for (int i = 0; i < aValue.length() && i < 256; i++) {
            char c = aValue.charAt(i);
            sb.append(Character.isWhitespace(c) || Character.isISOControl(c) || c == '=' ? '_' : c);
        }
        return sb.toString();
    }
}
