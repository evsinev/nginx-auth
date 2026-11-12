package com.payneteasy.nginxauth.webauthn.storage;

/**
 * Recovery enrollment grant. Only the SHA-256 of the secret is stored.
 */
public record EnrollmentGrant(
        String grantId,
        String secretHash,
        long expiresAt,
        int usesLeft,
        String issuedBy,
        long issuedAt
) {

    public boolean isUsable(long aNow) {
        return usesLeft > 0 && aNow < expiresAt;
    }

    public EnrollmentGrant used() {
        return new EnrollmentGrant(grantId, secretHash, expiresAt, usesLeft - 1, issuedBy, issuedAt);
    }
}
