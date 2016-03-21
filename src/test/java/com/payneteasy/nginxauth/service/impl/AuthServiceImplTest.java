package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.UserMustChangePasswordException;

import javax.naming.AuthenticationException;

public class AuthServiceImplTest {

    public static void main(String[] args) throws AuthenticationException {

        AuthServiceImpl authService = new AuthServiceImpl();
        try {
            authService.authenticate(args[0], args[1], true);
        } catch (UserMustChangePasswordException userMustChangePassword) {
            authService.changePassword(args[0], args[1], "123");
        }
    }
}
