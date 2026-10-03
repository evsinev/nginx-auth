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
    private final String               browserBinding;
    private final String               loginName;
    private final long                 loginGeneration;

    private Session(String canonicalUid, String displayName, List<String> groups, AuthenticationMethod method,
                    long ldapAuthTime, long webauthnAuthTime, String credentialId, boolean userVerified, boolean backupEligible,
                    String browserBinding, String loginName, long loginGeneration) {
        this.canonicalUid     = canonicalUid;
        this.displayName      = displayName;
        this.groups           = groups == null ? Collections.emptyList() : List.copyOf(groups);
        this.method           = method;
        this.ldapAuthTime     = ldapAuthTime;
        this.webauthnAuthTime = webauthnAuthTime;
        this.credentialId     = credentialId;
        this.userVerified     = userVerified;
        this.backupEligible   = backupEligible;
        this.browserBinding   = browserBinding;
        this.loginName        = loginName;
        this.loginGeneration  = loginGeneration;
    }

    public static Session withoutWebAuthn(String uid, String displayName, List<String> groups, AuthenticationMethod method, long ldapAuthTime) {
        if (method == AuthenticationMethod.LDAP_WEBAUTHN) {
            throw new IllegalArgumentException("Use withWebAuthn for LDAP_WEBAUTHN sessions");
        }
        return new Session(uid, displayName, groups, method, ldapAuthTime, 0L, null, false, false, null, null, 0L);
    }

    public static Session withWebAuthn(String uid, String displayName, List<String> groups, long ldapAuthTime,
                                       long webauthnAuthTime, String credentialId, boolean userVerified, boolean backupEligible) {
        if (credentialId == null) {
            throw new IllegalArgumentException("credentialId is required");
        }
        return new Session(uid, displayName, groups, AuthenticationMethod.LDAP_WEBAUTHN, ldapAuthTime, webauthnAuthTime,
                credentialId, userVerified, backupEligible, null, null, 0L);
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

    /** Browser binding the session was issued in, or null outside WebAuthn mode. */
    public String getBrowserBinding() {
        return browserBinding;
    }

    public Session boundTo(String aBrowserBinding) {
        return new Session(canonicalUid, displayName, groups, method, ldapAuthTime, webauthnAuthTime, credentialId,
                userVerified, backupEligible, aBrowserBinding, loginName, loginGeneration);
    }

    /** The typed login that selected the bind DN; lets a password change revoke sessions of that entry. */
    public String getLoginName() {
        return loginName;
    }

    /** Password-change revocation generation of the login name, read before the LDAP bind. */
    public long getLoginGeneration() {
        return loginGeneration;
    }

    public Session withLogin(String aLoginName, long aLoginGeneration) {
        return new Session(canonicalUid, displayName, groups, method, ldapAuthTime, webauthnAuthTime, credentialId,
                userVerified, backupEligible, browserBinding, aLoginName, aLoginGeneration);
    }
}
