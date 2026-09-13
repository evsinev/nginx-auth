package com.payneteasy.nginxauth.service;

public interface ITokenManager {

    String createToken(String username);

    boolean validateToken(String aTokenValue);

    void invalidateToken(String aTokenValue);

}
