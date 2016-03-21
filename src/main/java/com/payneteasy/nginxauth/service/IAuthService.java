package com.payneteasy.nginxauth.service;

import javax.naming.AuthenticationException;

/**
 *
 */
public interface IAuthService {

    void authenticate(String aUsername, String aPassword, long aVerificationCode, boolean aCanCheckAccess) throws AuthenticationException, UserMustChangePasswordException;

    void authenticate(String aUsername, String aPassword, boolean aCanCheckAccess) throws AuthenticationException, UserMustChangePasswordException;

    void changePassword(String aUsername, String aCurrentPassword, String aNewPassword) throws AuthenticationException;

}
