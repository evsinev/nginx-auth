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
        String enrolledCredentialId
) {

    public static PreAuth create(LdapPrincipal aPrincipal, String aPolicyId, String aBack) {
        return new PreAuth(SecureTokens.random(), aPrincipal, aPolicyId, aBack, null, null);
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
        return new PreAuth(preauthId, principal, policyId, back, aGrantId, enrolledCredentialId);
    }

    public PreAuth withEnrolledCredential(String aCredentialId) {
        return new PreAuth(preauthId, principal, policyId, back, null, aCredentialId);
    }
}
