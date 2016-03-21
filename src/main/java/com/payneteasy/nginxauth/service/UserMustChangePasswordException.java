package com.payneteasy.nginxauth.service;

public class UserMustChangePasswordException extends Exception {

    public UserMustChangePasswordException() {
        super();
    }

    public UserMustChangePasswordException(String message) {
        super(message);
    }
}
