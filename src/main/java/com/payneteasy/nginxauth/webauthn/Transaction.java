package com.payneteasy.nginxauth.webauthn;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

import java.util.List;

/**
 * Server-side state of one WebAuthn ceremony. The principal, policy and back URL are a snapshot taken at
 * start; finish never reads them from the request.
 */
public record Transaction(
        String transactionId,
        String binding,
        Purpose purpose,
        String uid,
        String displayName,
        List<String> groups,
        String preauthId,
        long ldapAuthTime,
        String sourceSessionId,
        String policyId,
        String back,
        String expectedOrigin,
        AssertionRequest assertionRequest,
        PublicKeyCredentialCreationOptions creationOptions,
        boolean attestationDirect,
        boolean bootstrap,
        String grantId,
        String targetCredentialId,
        boolean confirmLast,
        long resetEpoch,
        long createdAt,
        long expiresAt
) {

    public Transaction {
        groups = groups == null ? List.of() : List.copyOf(groups);
        if ((assertionRequest == null) == (creationOptions == null)) {
            throw new IllegalArgumentException("Exactly one of assertionRequest and creationOptions is required");
        }
    }

    public boolean isCreation() {
        return creationOptions != null;
    }
}
