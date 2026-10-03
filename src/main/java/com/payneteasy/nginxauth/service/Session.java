package com.payneteasy.nginxauth.service;

import java.util.Collections;
import java.util.List;

/**
 * Immutable authenticated session. The AUTH_TOKEN is the key in {@link ITokenManager}, not a field here.
 */
public final class Session {

    private final String               canonicalUid;
    private final String               displayName;
    private final List<String>         groups;
    private final AuthenticationMethod method;
    private final long                 ldapAuthTime;
    private final long                 webauthnAuthTime;
    private final String               credentialId;
    private final boolean              userVerified;
    private final boolean              backupEligible;

    private Session(String canonicalUid, String displayName, List<String> groups, AuthenticationMethod method,
                    long ldapAuthTime, long webauthnAuthTime, String credentialId, boolean userVerified, boolean backupEligible) {
        this.canonicalUid     = canonicalUid;
        this.displayName      = displayName;
        this.groups           = groups == null ? Collections.emptyList() : List.copyOf(groups);
        this.method           = method;
        this.ldapAuthTime     = ldapAuthTime;
        this.webauthnAuthTime = webauthnAuthTime;
        this.credentialId     = credentialId;
        this.userVerified     = userVerified;
        this.backupEligible   = backupEligible;
    }

    public static Session withoutWebAuthn(String uid, String displayName, List<String> groups, AuthenticationMethod method, long ldapAuthTime) {
        if (method == AuthenticationMethod.LDAP_WEBAUTHN) {
            throw new IllegalArgumentException("Use withWebAuthn for LDAP_WEBAUTHN sessions");
        }
        return new Session(uid, displayName, groups, method, ldapAuthTime, 0L, null, false, false);
    }

    public static Session withWebAuthn(String uid, String displayName, List<String> groups, long ldapAuthTime,
                                       long webauthnAuthTime, String credentialId, boolean userVerified, boolean backupEligible) {
        if (credentialId == null) {
            throw new IllegalArgumentException("credentialId is required");
        }
        return new Session(uid, displayName, groups, AuthenticationMethod.LDAP_WEBAUTHN, ldapAuthTime, webauthnAuthTime,
                credentialId, userVerified, backupEligible);
    }

    public String getCanonicalUid() {
        return canonicalUid;
    }

    public String getDisplayName() {
        return displayName;
    }

    public List<String> getGroups() {
        return groups;
    }

    public AuthenticationMethod getMethod() {
        return method;
    }

    public long getLdapAuthTime() {
        return ldapAuthTime;
    }

    public long getWebauthnAuthTime() {
        return webauthnAuthTime;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public boolean isUserVerified() {
        return userVerified;
    }

    public boolean isBackupEligible() {
        return backupEligible;
    }
}
