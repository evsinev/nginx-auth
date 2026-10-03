package com.payneteasy.nginxauth.webauthn.storage;

public class DuplicateCredentialException extends StorageException {

    public DuplicateCredentialException(String message) {
        super(message);
    }
}
