package com.payneteasy.nginxauth.service;

/**
 *
 */
public interface IOneTimePasswordService {

    boolean checkCode(String aUsername, long aCode);

    void dummyCheck(long aCode);

    boolean hasSecret(String aUsername);

    /**
     * Name the TOTP secret of this login is stored under, matching spellings LDAP treats as the same login;
     * null when the login has no secret.
     */
    default String resolveSecretName(String aUsername) {
        return hasSecret(aUsername) ? aUsername : null;
    }
}
