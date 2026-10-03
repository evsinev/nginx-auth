package com.payneteasy.nginxauth.policy;

import java.util.Collection;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Combination of all rules that apply to a user at a location.
 */
public final class EffectivePolicy {

    public static final EffectivePolicy NONE = new EffectivePolicy(false, false, null, null);

    private final boolean     requireWebAuthn;
    private final boolean     requireSingleDeviceCredential;
    private final Set<String> allowedAaguids;
    private final Long        maxAuthAgeSeconds;

    private EffectivePolicy(boolean requireWebAuthn, boolean requireSingleDeviceCredential, Set<String> allowedAaguids, Long maxAuthAgeSeconds) {
        this.requireSingleDeviceCredential = requireSingleDeviceCredential;
        this.allowedAaguids                = allowedAaguids == null ? null : Set.copyOf(allowedAaguids);
        this.maxAuthAgeSeconds             = maxAuthAgeSeconds;
        this.requireWebAuthn               = requireWebAuthn || requireSingleDeviceCredential || allowedAaguids != null || maxAuthAgeSeconds != null;
    }

    /**
     * requireWebAuthn: OR, requireSingleDeviceCredential: OR, allowedAaguids: intersection of the set ones,
     * maxAuthAge: minimum.
     */
    public static EffectivePolicy combine(Collection<PolicyRule> aRules) {
        boolean     requireWebAuthn = false;
        boolean     singleDevice    = false;
        Set<String> aaguids         = null;
        Long        maxAge          = null;
        for (PolicyRule rule : aRules) {
            requireWebAuthn |= rule.requireWebAuthn();
            singleDevice    |= rule.requireSingleDeviceCredential();
            if (rule.allowedAaguids() != null) {
                if (aaguids == null) {
                    aaguids = new HashSet<>(rule.allowedAaguids());
                } else {
                    aaguids.retainAll(rule.allowedAaguids());
                }
            }
            if (rule.maxAuthAgeSeconds() != null) {
                maxAge = maxAge == null ? rule.maxAuthAgeSeconds() : Math.min(maxAge, rule.maxAuthAgeSeconds());
            }
        }
        return new EffectivePolicy(requireWebAuthn, singleDevice, aaguids, maxAge);
    }

    public boolean requireWebAuthn() {
        return requireWebAuthn;
    }

    public boolean requireSingleDeviceCredential() {
        return requireSingleDeviceCredential;
    }

    /** {@code null} when not set; an empty set means nothing is allowed. */
    public Set<String> allowedAaguids() {
        return allowedAaguids;
    }

    public Long maxAuthAgeSeconds() {
        return maxAuthAgeSeconds;
    }

    /** Empty AAGUID intersection: no credential can satisfy the policy. */
    public boolean denyAll() {
        return allowedAaguids != null && allowedAaguids.isEmpty();
    }

    public boolean isEligible(boolean aBackupEligible, String aAaguid) {
        if (requireSingleDeviceCredential && aBackupEligible) {
            return false;
        }
        if (allowedAaguids != null) {
            return aAaguid != null && allowedAaguids.contains(aAaguid.toLowerCase(Locale.ROOT));
        }
        return true;
    }
}
