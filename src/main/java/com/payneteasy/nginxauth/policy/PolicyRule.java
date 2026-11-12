package com.payneteasy.nginxauth.policy;

import java.util.Set;

/**
 * One rule from the policy file. {@code null} means "not set".
 */
public record PolicyRule(
        boolean requireWebAuthn,
        boolean requireSingleDeviceCredential,
        Set<String> allowedAaguids,
        Long maxAuthAgeSeconds
) {

    public PolicyRule {
        allowedAaguids = allowedAaguids == null ? null : Set.copyOf(allowedAaguids);
    }

    public static final PolicyRule EMPTY = new PolicyRule(false, false, null, null);

    /** Any requirement that only makes sense with WebAuthn enabled. */
    public boolean hasWebAuthnRequirement() {
        return requireWebAuthn || requireSingleDeviceCredential || allowedAaguids != null || maxAuthAgeSeconds != null;
    }
}
