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
//        cookie.setHttpOnly(true);
        // cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(-1); // will be deleted when the Web browser exits

        theResponse.addCookie(cookie);
    }

    private Map<String, Cookie> theMap;
    private final HttpServletRequest theRequest;
    private final HttpServletResponse theResponse;

}
