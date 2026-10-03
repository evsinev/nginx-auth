package com.payneteasy.nginxauth.ldap;

import java.text.Normalizer;
import java.util.Locale;

/**
 * Comparison form of a login name, following LDAP caseIgnoreMatch preparation (RFC 4518 §2): map
 * (§2.2: some code points to nothing, separators and some controls to space), case fold, NFKC, then
 * insignificant space handling (trim, collapse). Spellings that select the same bind DN compare equal;
 * names LDAP keeps apart (ı and i) stay apart.
 *
 * <p>Used only to find what a password change must revoke and to key the login limiter. The TOTP secret is
 * looked up by the exact typed name, so an imperfect match here never selects another account's factor.
 */
public final class LoginNames {

    private static final int DOTLESS_I = 0x0131;

    private LoginNames() {
    }

    public static String normalize(String aLoginName) {
        if (aLoginName == null) {
            return null;
        }
        String folded = fold(map(aLoginName));
        String nfkc = Normalizer.normalize(folded, Normalizer.Form.NFKC);
        StringBuilder sb = new StringBuilder(nfkc.length());
        boolean space = false;
        for (int i = 0; i < nfkc.length(); i++) {
            char c = nfkc.charAt(i);
            if (c == ' ') {
                space = sb.length() > 0;
                continue;
            }
            if (space) {
                sb.append(' ');
                space = false;
            }
            sb.append(c);
        }
        return sb.toString();
    }

    /** RFC 4518 §2.2 Map, from its fixed lists (not from Java's idea of whitespace). */
    static String map(String aValue) {
        StringBuilder sb = new StringBuilder(aValue.length());
        aValue.codePoints().forEach(cp -> {
            if (toSpace(cp)) {
                sb.append(' ');
            } else if (!toNothing(cp)) {
                sb.appendCodePoint(cp);
            }
        });
        return sb.toString();
    }

    private static boolean toSpace(int cp) {
        if (cp == 0x0009 || cp == 0x000A || cp == 0x000B || cp == 0x000C || cp == 0x000D || cp == 0x0085) {
            return true;
        }
        int type = Character.getType(cp);
        return type == Character.SPACE_SEPARATOR || type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR;
    }

    private static boolean toNothing(int cp) {
        return cp == 0x00AD || cp == 0x1806 || cp == 0x034F || (cp >= 0x180B && cp <= 0x180D)
                || (cp >= 0xFE00 && cp <= 0xFE0F) || cp == 0xFFFC || cp == 0x200B
                // controls and format characters listed in §2.2
                || (cp >= 0x0000 && cp <= 0x0008) || (cp >= 0x000E && cp <= 0x001F) || (cp >= 0x007F && cp <= 0x0084)
                || (cp >= 0x0086 && cp <= 0x009F) || cp == 0x06DD || cp == 0x070F || cp == 0x180E
                || (cp >= 0x200C && cp <= 0x200F) || (cp >= 0x202A && cp <= 0x202E) || (cp >= 0x2060 && cp <= 0x2063)
                || (cp >= 0x206A && cp <= 0x206F) || cp == 0xFEFF || (cp >= 0xFFF9 && cp <= 0xFFFB)
                || (cp >= 0x1D173 && cp <= 0x1D17A) || cp == 0xE0001 || (cp >= 0xE0020 && cp <= 0xE007F);
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
