package com.payneteasy.nginxauth.util;

import com.payneteasy.nginxauth.service.ITokenManager;
import com.payneteasy.nginxauth.service.impl.TokenManagerImpl;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CheckCookiesAccess {

    private static final String TOKEN_COOKIE_NAME = SettingsManager.getTokenCookieName();

    private final ITokenManager tokenManager = TokenManagerImpl.getInstance();

    public boolean isValidToken(HttpServletRequest aRequest, HttpServletResponse aResponse) {
        CookiesManager cookies = new CookiesManager(aRequest, aResponse);
        String         token   = cookies.getCookieValue(TOKEN_COOKIE_NAME);
        if (token == null) {
            token = aRequest.getParameter(TOKEN_COOKIE_NAME);
        }

        return tokenManager.validateToken(token);
    }


}
