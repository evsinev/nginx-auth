package com.payneteasy.nginxauth.util;

/**
 */
public class StringUtils {

    public static boolean isEmpty(String aText) {
        return aText==null || aText.length()==0 || aText.trim().length()==0;
    }
}
