package com.payneteasy.nginxauth.service;

import javax.naming.AuthenticationException;

/**
 *
 */
public interface IAuthService {
    void authenticate(String aUsername, String aPassword, long aVerificationCode) throws AuthenticationException;
}
