package com.payneteasy.nginxauth.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

public class CookiesManager {

    private static final boolean SECURE_COOKIE = SettingsManager.getSecureCookie();
    private static final String TOKEN_COOKIE_NAME = SettingsManager.getTokenCookieName();
    private static final String TOKEN_COOKIE_ASSIGNED_NAME = SettingsManager.getTokenCookieAssignedName();

    private Map<String, Cookie> theMap;
    private final HttpServletRequest theRequest;
    private final HttpServletResponse theResponse;

    public CookiesManager(HttpServletRequest aRequest, HttpServletResponse aResponse) {
        theRequest = aRequest;
        theResponse = aResponse;
    }

    public String getCookieValue(String aKey) {
        if(theMap==null) {
            Cookie[] cookies = theRequest.getCookies();
            if(cookies!=null) {
                theMap = new HashMap<String, Cookie>(cookies.length+cookies.length/2);
                for (Cookie cookie : cookies) {
                    theMap.put(cookie.getName(), cookie);
                }
            } else {
                theMap = new HashMap<String, Cookie>();
                return null;
            }
        }

        Cookie cookie = theMap.get(aKey);
        return cookie!=null ? cookie.getValue() : null;
    }

    public void add(String aKey, String aValue) {
        Cookie cookie = new Cookie(aKey, aValue);
        cookie.setHttpOnly(true);
        if (SECURE_COOKIE) {
            cookie.setSecure(true);
        }
        cookie.setPath("/");
        cookie.setMaxAge(-1);
        theResponse.addCookie(cookie);
    }

    public void addAssignedMarker(String aKey, String aValue) {
        Cookie cookie = new Cookie(aKey, aValue);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(-1);
        theResponse.addCookie(cookie);
    }

    public boolean hasCookie(String aCookieName) {
        return getCookieValue(aCookieName) != null;
    }

    public void clear() {
        expire(TOKEN_COOKIE_NAME, SECURE_COOKIE);
        expire(TOKEN_COOKIE_ASSIGNED_NAME, false);
    }

    private void expire(String name, boolean secure) {
        Cookie cookie = new Cookie(name, "");
        cookie.setHttpOnly(true);
        if (secure) {
            cookie.setSecure(true);
        }
        cookie.setPath("/");
        cookie.setMaxAge(0);
        theResponse.addCookie(cookie);
    }
}
