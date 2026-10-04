package com.payneteasy.nginxauth.webauthn.storage;

import java.util.List;

/**
 * Registered WebAuthn credential. Binary values are base64url without padding.
 * {@code lastUsedAt} is 0 when never used.
 */
public record StoredCredential(
        String credentialId,
        String publicKeyCose,
        long signCount,
        String aaguid,
        boolean backupEligible,
        boolean backupState,
        List<String> transports,
        String name,
        long createdAt,
        long lastUsedAt
) {

    public StoredCredential {
        transports = transports == null ? List.of() : List.copyOf(transports);
    }

    public StoredCredential afterUse(long aSignCount, boolean aBackupState, long aNow) {
        return new StoredCredential(credentialId, publicKeyCose, aSignCount, aaguid, backupEligible, aBackupState,
                transports, name, createdAt, aNow);
    }
}
