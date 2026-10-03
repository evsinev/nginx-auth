package com.payneteasy.nginxauth.policy;

import com.payneteasy.nginxauth.service.AuthenticationMethod;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.webauthn.storage.IWebAuthnCredentialRepository;
import com.payneteasy.nginxauth.webauthn.storage.StoredCredential;
import com.payneteasy.nginxauth.webauthn.storage.UserRecord;

import java.util.Optional;
import java.util.function.LongSupplier;

/**
 * Checks a session against the effective policy of a location on every auth_request.
 */
public final class AccessChecker {

    public enum Decision {
        ALLOW,
        /** Authenticated, but WebAuthn (or a fresher / different credential) is required. */
        STEP_UP,
        /** The session cannot be used at all. */
        DENY
    }

    private final PolicyResolver resolver;
    private final IWebAuthnCredentialRepository repository;
    private final LongSupplier clock;

    public AccessChecker(PolicyResolver aResolver, IWebAuthnCredentialRepository aRepository, LongSupplier aClock) {
        resolver = aResolver;
        repository = aRepository;
        clock = aClock;
    }

    /** policyId must already be known ({@link PolicyResolver#isKnownPolicyId}). */
    public Decision check(Session aSession, String aPolicyId) {
        EffectivePolicy policy = resolver.resolve(aSession.getGroups(), aPolicyId);
        if (policy.denyAll()) {
            return Decision.DENY;
        }
        if (aSession.getMethod() == AuthenticationMethod.LDAP_WEBAUTHN) {
            Optional<StoredCredential> credential = sessionCredential(aSession);
            if (credential.isEmpty()) {
                return Decision.DENY;
            }
            if (!policy.isEligible(credential.get().backupEligible(), credential.get().aaguid())) {
                return Decision.STEP_UP;
            }
        } else if (policy.requireWebAuthn()) {
            return Decision.STEP_UP;
        }
        Long maxAge = policy.maxAuthAgeSeconds();
        if (maxAge != null && clock.getAsLong() - aSession.getWebauthnAuthTime() > maxAge * 1000L) {
            return Decision.STEP_UP;
        }
        return Decision.ALLOW;
    }

    /** The credential an LDAP_WEBAUTHN session was issued with, if it still exists for the same user. */
    public Optional<StoredCredential> sessionCredential(Session aSession) {
        String credentialId = aSession.getCredentialId();
        if (credentialId == null || repository == null) {
            return Optional.empty();
        }
        Optional<String> owner = repository.ownerOfCredential(credentialId);
        if (owner.isEmpty() || !owner.get().equals(aSession.getCanonicalUid())) {
            return Optional.empty();
        }
        return repository.find(owner.get()).flatMap(record -> record.find(credentialId));
    }

    public boolean isSessionCredentialValid(Session aSession) {
        return aSession.getMethod() != AuthenticationMethod.LDAP_WEBAUTHN || sessionCredential(aSession).isPresent();
    }

    public static boolean hasEligible(UserRecord aRecord, EffectivePolicy aPolicy) {
        if (aRecord == null) {
            return false;
        }
        for (StoredCredential credential : aRecord.credentials()) {
            if (aPolicy.isEligible(credential.backupEligible(), credential.aaguid())) {
                return true;
            }
        }
        return false;
    }
}
