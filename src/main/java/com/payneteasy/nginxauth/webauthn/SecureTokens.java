package com.payneteasy.nginxauth.webauthn;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

public final class SecureTokens {

    private static final SecureRandom RANDOM = new SecureRandom();

    private SecureTokens() {
    }

    /** 256-bit random value, base64url without padding. */
    public static String random() {
        return random(32);
    }

    public static String random(int aBytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(aBytes));
    }

    public static byte[] randomBytes(int aBytes) {
        byte[] bytes = new byte[aBytes];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    public static boolean constantTimeEquals(String aExpected, String aActual) {
        if (aExpected == null || aActual == null) {
            return false;
        }
        return MessageDigest.isEqual(aExpected.getBytes(StandardCharsets.UTF_8), aActual.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] sha256(byte[] aData) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(aData);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /** Short non-reversible reference for logs. */
    public static String shortHash(String aValue) {
        if (aValue == null) {
            return "-";
        }
        return HexFormat.of().formatHex(sha256(aValue.getBytes(StandardCharsets.UTF_8))).substring(0, 12);
    }
}
