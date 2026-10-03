package com.payneteasy.nginxauth.webauthn;

import com.payneteasy.nginxauth.policy.EffectivePolicy;

/**
 * Chooses the second factor after a successful LDAP check. A WebAuthn failure never falls back to TOTP:
 * the TOTP branch is reachable only when the policy does not require WebAuthn.
 */
public final class MethodSelector {

    public enum Method {
        WEBAUTHN,
        /** WebAuthn required but no usable credential: only an enrollment grant can help. */
        RECOVERY,
        TOTP,
        /** TOTP is the only option and no code was entered. */
        CODE_REQUIRED,
        LDAP_ONLY,
        DENY
    }

    private MethodSelector() {
    }

    public static Method select(EffectivePolicy aPolicy, boolean aOtpEnabled, boolean aCodeProvided,
                                boolean aHasEligibleCredentials, boolean aWebAuthnUsable) {
        if (aPolicy.denyAll()) {
            return Method.DENY;
        }
        if (aPolicy.requireWebAuthn()) {
            if (!aWebAuthnUsable) {
                return Method.DENY;
            }
            return aHasEligibleCredentials ? Method.WEBAUTHN : Method.RECOVERY;
        }
        if (aOtpEnabled && aCodeProvided) {
            return Method.TOTP;
        }
        if (aHasEligibleCredentials && aWebAuthnUsable) {
            return Method.WEBAUTHN;
        }
        if (aOtpEnabled) {
            return Method.CODE_REQUIRED;
        }
        return Method.LDAP_ONLY;
    }
}
