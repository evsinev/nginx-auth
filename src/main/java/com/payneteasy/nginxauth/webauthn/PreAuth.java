package com.payneteasy.nginxauth.webauthn;

import com.payneteasy.nginxauth.ldap.LdapPrincipal;

/**
 * Successful LDAP check waiting for the second factor. Lives in the browser state, never holds the password.
 * Copies keep the same {@code preauthId}; a new LDAP login creates a new id.
 */
public record PreAuth(
        String preauthId,
        LdapPrincipal principal,
        String policyId,
        String back,
        String recoveryGrantId,
        String enrolledCredentialId,
        long loginGeneration,
        long loginSequence
) {

    /**
     * @param aLoginGeneration {@link LoginRevocations} generation read before the LDAP bind
     */
    public static PreAuth create(LdapPrincipal aPrincipal, String aPolicyId, String aBack, long aLoginGeneration) {
        return create(aPrincipal, aPolicyId, aBack, aLoginGeneration, 0L);
    }

    /**
     * @param aLoginSequence {@code WebAuthnService.nextLoginSequence()} taken before the LDAP bind
     */
    public static PreAuth create(LdapPrincipal aPrincipal, String aPolicyId, String aBack, long aLoginGeneration, long aLoginSequence) {
        return new PreAuth(SecureTokens.random(), aPrincipal, aPolicyId, aBack, null, null, aLoginGeneration, aLoginSequence);
    }

    public String loginName() {
        return principal.getLoginName();
    }

    public String uid() {
        return principal.getCanonicalUid();
    }

    public long ldapAuthTime() {
        return principal.getLdapAuthTime();
    }

    public boolean isLive(long aNow, long aTtlMillis) {
        return aNow - principal.getLdapAuthTime() <= aTtlMillis;
    }

    public PreAuth withRecoveryGrant(String aGrantId) {
        return new PreAuth(preauthId, principal, policyId, back, aGrantId, enrolledCredentialId, loginGeneration, loginSequence);
    }

    public PreAuth withEnrolledCredential(String aCredentialId) {
        return new PreAuth(preauthId, principal, policyId, back, null, aCredentialId, loginGeneration, loginSequence);
    }
}
