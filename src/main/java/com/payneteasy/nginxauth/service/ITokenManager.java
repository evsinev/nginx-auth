package com.payneteasy.nginxauth.service;

import java.util.Optional;

public interface ITokenManager {

    String createToken(String username);

    String createSession(Session aSession);

    boolean validateToken(String aTokenValue);

    /** Returns a live session and extends its inactivity timeout. */
    Optional<Session> getSession(String aTokenValue);

    /** Returns a live session without touching its inactivity timeout. */
    Optional<Session> peekSession(String aTokenValue);

    /**
     * Atomically replaces a live session with a new one: the old token stops working and a new token is returned.
     * Returns empty if the old session is gone or expired; at most one caller wins per old token.
     */
    Optional<String> replaceIfActive(String aOldToken, Session aNewSession);

    void invalidateToken(String aTokenValue);

    void invalidateUser(String aCanonicalUid);

    void invalidateByCredential(String aCanonicalUid, String aCredentialId);

    void invalidateByBrowserBinding(String aBrowserBinding);

    /** Login names select the bind DN and compare case-insensitively, like LDAP attribute values. */
    void invalidateByLoginName(String aLoginName);

}
