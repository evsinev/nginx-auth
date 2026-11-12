package com.payneteasy.nginxauth.webauthn;

import org.apache.commons.codec.binary.Base32;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

/**
 * Recovery enrollment secret: 160 random bits, base32 in groups of four. Only the hash is stored.
 */
public final class EnrollmentSecrets {

    private EnrollmentSecrets() {
    }

    public static String generate() {
        String base32 = new Base32().encodeAsString(SecureTokens.randomBytes(20)).replace("=", "");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < base32.length(); i++) {
            if (i > 0 && i % 4 == 0) {
                sb.append('-');
            }
            sb.append(base32.charAt(i));
        }
        return sb.toString();
    }

    public static String normalize(String aInput) {
        if (aInput == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < aInput.length(); i++) {
            char c = aInput.charAt(i);
            if (c == '-' || Character.isWhitespace(c)) {
                continue;
            }
            sb.append(c);
        }
        return sb.toString().toUpperCase(Locale.ROOT);
    }

    public static String hash(String aSecret) {
        byte[] digest = SecureTokens.sha256(normalize(aSecret).getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    public static boolean matches(String aInput, String aStoredHash) {
        return SecureTokens.constantTimeEquals(aStoredHash, hash(aInput));
    }
}
