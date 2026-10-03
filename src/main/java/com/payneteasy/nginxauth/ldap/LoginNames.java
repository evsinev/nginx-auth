package com.payneteasy.nginxauth.ldap;

import java.text.Normalizer;
import java.util.Locale;

/**
 * Comparison form of a login name, close to LDAP caseIgnoreMatch (RFC 4518): Unicode NFKC, leading and
 * trailing spaces removed, inner whitespace runs collapsed to one space, case folded as RFC 3454 B.2.
 * Spellings that select the same bind DN compare equal; names LDAP keeps apart (ı and i) stay apart.
 */
public final class LoginNames {

    private static final int DOTLESS_I = 0x0131;

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
        return fold(sb.toString());
    }

    /**
     * Case folding per code point, matching RFC 3454 table B.2 for the cases that matter here (ß → ss,
     * ſ → s, ς → σ, İ → i̇) without the one place where upper-then-lower diverges from it: dotless ı (U+0131)
     * has no B.2 mapping and must stay distinct from i, otherwise two accounts would merge.
     */
    static String fold(String aValue) {
        StringBuilder sb = new StringBuilder(aValue.length());
        aValue.codePoints().forEach(cp -> {
            if (cp == DOTLESS_I) {
                sb.appendCodePoint(cp);
            } else {
                sb.append(new String(Character.toChars(cp)).toUpperCase(Locale.ROOT).toLowerCase(Locale.ROOT));
            }
        });
        return sb.toString();
    }

    public static boolean same(String aFirst, String aSecond) {
        return aFirst != null && aSecond != null && normalize(aFirst).equals(normalize(aSecond));
    }
}
