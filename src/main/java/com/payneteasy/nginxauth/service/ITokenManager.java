package com.payneteasy.nginxauth.service;

/**
 *
 */
public interface ITokenManager {

    String createToken();

    boolean validateToken(String aTokenValue);

}
