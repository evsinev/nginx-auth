package com.payneteasy.nginxauth.webauthn.storage;

import java.util.Optional;

/**
 * Credential storage. Mutations require {@code locks().withLock(uid, ...)} held by the caller,
 * so read–check–update is atomic per user.
 */
public interface IWebAuthnCredentialRepository {

    UserLocks locks();

    Optional<UserRecord> find(String aUid);

    Optional<String> ownerOfCredential(String aCredentialId);

    Optional<String> uidForUserHandle(String aUserHandle);

    /**
     * Writes the record. New credential IDs are reserved globally before the write.
     *
     * @throws DuplicateCredentialException if a new credential ID or the user handle belongs to another user
     */
    void save(UserRecord aRecord) throws StorageException;

    boolean isFailed();
}
