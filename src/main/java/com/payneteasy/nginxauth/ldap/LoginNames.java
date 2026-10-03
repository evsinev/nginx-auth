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
     * Case folding per code point: simple lower case, plus the RFC 3454 B.2 mappings that lower case does not
     * produce. No round trip through upper case, so letters without a B.2 mapping stay as they are (dotless ı
     * does not become i, U+1C80 does not become в). Compatibility forms (ligatures, ﬀ) are handled by NFKC.
     */
    static String fold(String aValue) {
        StringBuilder sb = new StringBuilder(aValue.length());
        aValue.codePoints().forEach(cp -> {
            if (cp == 0x0130) {
                sb.append("i\u0307");
                return;
            }
            int lower = Character.toLowerCase(cp);
            String special = FULL_FOLDS.get(lower);
            if (special != null) {
                sb.append(special);
            } else {
                sb.appendCodePoint(lower);
            }
        });
        return sb.toString();
    }

    /** RFC 3454 B.2 entries for code points that are already lower case (or become so) but still fold. */
    private static final java.util.Map<Integer, String> FULL_FOLDS = java.util.Map.ofEntries(
            java.util.Map.entry(0x00DF, "ss"),            // ß
            java.util.Map.entry(0x0149, "\u02BCn"),       // ŉ
            java.util.Map.entry(0x017F, "s"),             // ſ
            java.util.Map.entry(0x01F0, "j\u030C"),       // ǰ
            java.util.Map.entry(0x0345, "\u03B9"),        // combining ypogegrammeni → ι
            java.util.Map.entry(0x0390, "\u03B9\u0308\u0301"),
            java.util.Map.entry(0x03B0, "\u03C5\u0308\u0301"),
            java.util.Map.entry(0x03C2, "\u03C3"),        // ς → σ
            java.util.Map.entry(0x03D0, "\u03B2"),        // ϐ → β
            java.util.Map.entry(0x03D1, "\u03B8"),        // ϑ → θ
            java.util.Map.entry(0x03D5, "\u03C6"),        // ϕ → φ
            java.util.Map.entry(0x03D6, "\u03C0"),        // ϖ → π
            java.util.Map.entry(0x03F0, "\u03BA"),        // ϰ → κ
            java.util.Map.entry(0x03F1, "\u03C1"),        // ϱ → ρ
            java.util.Map.entry(0x03F5, "\u03B5"),        // ϵ → ε
            java.util.Map.entry(0x0587, "\u0565\u0582"), // և
            java.util.Map.entry(0x1E96, "h\u0331"),
            java.util.Map.entry(0x1E97, "t\u0308"),
            java.util.Map.entry(0x1E98, "w\u030A"),
            java.util.Map.entry(0x1E99, "y\u030A"),
            java.util.Map.entry(0x1E9A, "a\u02BE"),
            java.util.Map.entry(0x1E9B, "\u1E61")         // ẛ → ṡ
    );

    public static boolean same(String aFirst, String aSecond) {
        return aFirst != null && aSecond != null && normalize(aFirst).equals(normalize(aSecond));
    }
}
