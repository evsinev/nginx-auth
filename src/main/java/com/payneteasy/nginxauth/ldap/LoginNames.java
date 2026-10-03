package com.payneteasy.nginxauth.ldap;

import java.text.Normalizer;
import java.util.Locale;

/**
 * Comparison form of a login name, close to LDAP caseIgnoreMatch (RFC 4518): Unicode NFKC, leading and
 * trailing spaces removed, inner whitespace runs collapsed to one space, case folded. Two spellings that
 * select the same bind DN compare equal.
 */
public final class LoginNames {

    private LoginNames() {
    }

    public static String normalize(String aLoginName) {
        if (aLoginName == null) {
            return null;
        }
        String nfkc = Normalizer.normalize(aLoginName, Normalizer.Form.NFKC);
        StringBuilder sb = new StringBuilder(nfkc.length());
        boolean space = false;
        for (int i = 0; i < nfkc.length(); i++) {
            char c = nfkc.charAt(i);
            if (Character.isWhitespace(c) || Character.isSpaceChar(c)) {
                space = sb.length() > 0;
                continue;
            }
            if (space) {
                sb.append(' ');
                space = false;
            }
            sb.append(c);
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }

    public static boolean same(String aFirst, String aSecond) {
        return aFirst != null && aSecond != null && normalize(aFirst).equals(normalize(aSecond));
    }
}
