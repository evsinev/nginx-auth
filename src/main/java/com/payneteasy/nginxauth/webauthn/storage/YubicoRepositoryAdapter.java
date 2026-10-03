package com.payneteasy.nginxauth.webauthn.storage;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.exception.Base64UrlException;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Exposes {@link IWebAuthnCredentialRepository} to Yubico. Usernames are canonical uids.
 */
public final class YubicoRepositoryAdapter implements CredentialRepository {

    private final IWebAuthnCredentialRepository repository;

    public YubicoRepositoryAdapter(IWebAuthnCredentialRepository aRepository) {
        repository = aRepository;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String aUsername) {
        Optional<UserRecord> record = repository.find(aUsername);
        if (record.isEmpty()) {
            return Collections.emptySet();
        }
        Set<PublicKeyCredentialDescriptor> descriptors = new HashSet<>();
        for (StoredCredential credential : record.get().credentials()) {
            descriptors.add(descriptor(credential));
        }
        return descriptors;
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String aUsername) {
        return repository.find(aUsername).map(record -> bytes(record.userHandle()));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray aUserHandle) {
        return repository.uidForUserHandle(aUserHandle.getBase64Url());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray aCredentialId, ByteArray aUserHandle) {
        String credentialId = aCredentialId.getBase64Url();
        Optional<String> owner = repository.ownerOfCredential(credentialId);
        if (owner.isEmpty()) {
            return Optional.empty();
        }
        Optional<UserRecord> record = repository.find(owner.get());
        if (record.isEmpty() || !record.get().userHandle().equals(aUserHandle.getBase64Url())) {
            return Optional.empty();
        }
        return record.get().find(credentialId).map(credential -> registered(record.get(), credential));
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray aCredentialId) {
        String credentialId = aCredentialId.getBase64Url();
        Optional<String> owner = repository.ownerOfCredential(credentialId);
        if (owner.isEmpty()) {
            return Collections.emptySet();
        }
        Optional<UserRecord> record = repository.find(owner.get());
        if (record.isEmpty()) {
            return Collections.emptySet();
        }
        return record.get().find(credentialId)
                .map(credential -> Collections.singleton(registered(record.get(), credential)))
                .orElse(Collections.emptySet());
    }

    public static PublicKeyCredentialDescriptor descriptor(StoredCredential aCredential) {
        Set<AuthenticatorTransport> transports = new TreeSet<>();
        for (String transport : aCredential.transports()) {
            transports.add(AuthenticatorTransport.of(transport));
        }
        PublicKeyCredentialDescriptor.PublicKeyCredentialDescriptorBuilder builder = PublicKeyCredentialDescriptor.builder()
                .id(bytes(aCredential.credentialId()));
        if (!transports.isEmpty()) {
            builder.transports(transports);
        }
        return builder.build();
    }

    private static RegisteredCredential registered(UserRecord aRecord, StoredCredential aCredential) {
        return RegisteredCredential.builder()
                .credentialId(bytes(aCredential.credentialId()))
                .userHandle(bytes(aRecord.userHandle()))
                .publicKeyCose(bytes(aCredential.publicKeyCose()))
                .signatureCount(aCredential.signCount())
                .backupEligible(aCredential.backupEligible())
                .backupState(aCredential.backupState())
                .build();
    }

    public static ByteArray bytes(String aBase64Url) {
        try {
            return ByteArray.fromBase64Url(aBase64Url);
        } catch (Base64UrlException e) {
            throw new IllegalStateException("Stored value is not base64url", e);
        }
    }
}
