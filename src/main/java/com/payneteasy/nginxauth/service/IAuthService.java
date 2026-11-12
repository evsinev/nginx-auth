package com.payneteasy.nginxauth.service;

import com.payneteasy.nginxauth.ldap.LdapPrincipal;

import javax.naming.AuthenticationException;

/**
 *
 */
public interface IAuthService {

    void authenticate(String aUsername, String aPassword, long aVerificationCode, boolean aCanCheckAccess) throws AuthenticationException, UserMustChangePasswordException;

    void authenticate(String aUsername, String aPassword, boolean aCanCheckAccess) throws AuthenticationException, UserMustChangePasswordException;

    /**
     * Binds as the user and reads uid, display name and groups from the directory.
     */
    LdapPrincipal authenticatePrincipal(String aUsername, String aPassword) throws AuthenticationException, UserMustChangePasswordException;

    void changePassword(String aUsername, String aCurrentPassword, String aNewPassword) throws AuthenticationException;

}
