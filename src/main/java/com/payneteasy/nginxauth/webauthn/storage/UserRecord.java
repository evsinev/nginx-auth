package com.payneteasy.nginxauth.webauthn.storage;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Immutable content of {@code <uid>.json}.
 */
public record UserRecord(
        String uid,
        String userHandle,
        EnrollmentGrant enrollmentGrant,
        List<StoredCredential> credentials
) {

    public static final int VERSION = 1;

    public UserRecord {
        credentials = credentials == null ? List.of() : List.copyOf(credentials);
    }

    public static UserRecord empty(String aUid, String aUserHandle) {
        return new UserRecord(aUid, aUserHandle, null, List.of());
    }

    public Optional<StoredCredential> find(String aCredentialId) {
        for (StoredCredential credential : credentials) {
            if (credential.credentialId().equals(aCredentialId)) {
                return Optional.of(credential);
            }
        }
        return Optional.empty();
    }

    public UserRecord withCredential(StoredCredential aCredential) {
        List<StoredCredential> list = new ArrayList<>();
        boolean replaced = false;
        for (StoredCredential credential : credentials) {
            if (credential.credentialId().equals(aCredential.credentialId())) {
                list.add(aCredential);
                replaced = true;
            } else {
                list.add(credential);
            }
        }
        if (!replaced) {
            list.add(aCredential);
        }
        return new UserRecord(uid, userHandle, enrollmentGrant, list);
    }

    public UserRecord withoutCredential(String aCredentialId) {
        List<StoredCredential> list = new ArrayList<>(credentials);
        list.removeIf(credential -> credential.credentialId().equals(aCredentialId));
        return new UserRecord(uid, userHandle, enrollmentGrant, list);
    }

    public UserRecord withoutCredentials() {
        return new UserRecord(uid, userHandle, enrollmentGrant, List.of());
    }

    public UserRecord withGrant(EnrollmentGrant aGrant) {
        return new UserRecord(uid, userHandle, aGrant, credentials);
    }
}
