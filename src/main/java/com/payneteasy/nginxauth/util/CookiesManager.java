package com.payneteasy.nginxauth.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
        applyCookieFlags(cookie, SECURE_COOKIE);
        cookie.setPath("/");
        cookie.setMaxAge(-1);
        theResponse.addCookie(cookie);
    }

    public void addAssignedMarker(String aKey, String aValue) {
        Cookie cookie = new Cookie(aKey, aValue);
        applyCookieFlags(cookie, false);
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
        applyCookieFlags(cookie, secure);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        theResponse.addCookie(cookie);
    }

    private static void applyCookieFlags(Cookie cookie, boolean secure) {
        cookie.setHttpOnly(true);
        if (secure) {
            cookie.setSecure(true);
        }
        cookie.setAttribute("SameSite", "Lax");
    }
}
