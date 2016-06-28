package com.payneteasy.nginxauth.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class CookiesManager {

    private static final boolean SECURE_COOKIE = SettingsManager.getSecureCookie();

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

        if(SECURE_COOKIE) {
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
        }

        cookie.setPath("/");
        cookie.setMaxAge(-1); // will be deleted when the Web browser exits

        theResponse.addCookie(cookie);
    }

    public void addUnsecure(String aKey, String aValue) {
        Cookie cookie = new Cookie(aKey, aValue);
        cookie.setPath("/");
        cookie.setMaxAge(-1); // will be deleted when the Web browser exits
        theResponse.addCookie(cookie);
    }

    public boolean hasCookie(String aCookieName) {
        return getCookieValue(aCookieName) != null;
    }

    public void clear() {
        Cookie[] cookies = theRequest.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                cookie.setValue("");
                cookie.setPath("/");
                cookie.setMaxAge(0);
                theResponse.addCookie(cookie);
            }
        }
    }
}
