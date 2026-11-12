package com.payneteasy.nginxauth.webauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One RelyingParty per allowed origin, so the library checks clientData.origin against the origin
 * fixed at ceremony start. Two flavours: attestation NONE and DIRECT (for AAGUID policies).
 */
public final class RelyingParties {

    /** Algorithms available in the JDK; the library default also lists ML-DSA, which needs an extra provider. */
    static final List<PublicKeyCredentialParameters> ALGORITHMS = List.of(
            PublicKeyCredentialParameters.ES256,
            PublicKeyCredentialParameters.EdDSA,
            PublicKeyCredentialParameters.ES384,
            PublicKeyCredentialParameters.ES512,
            PublicKeyCredentialParameters.RS256);

    private final Map<String, RelyingParty> none   = new HashMap<>();
    private final Map<String, RelyingParty> direct = new HashMap<>();

    public RelyingParties(WebAuthnConfig aConfig, CredentialRepository aRepository) {
        RelyingPartyIdentity identity = RelyingPartyIdentity.builder()
                .id(aConfig.getRpId())
                .name(aConfig.getRpName())
                .build();
        for (AllowedOrigin origin : aConfig.getAllowedOrigins()) {
            none.put(origin.getOrigin(), build(identity, aRepository, origin.getOrigin(), AttestationConveyancePreference.NONE));
            direct.put(origin.getOrigin(), build(identity, aRepository, origin.getOrigin(), AttestationConveyancePreference.DIRECT));
        }
    }

    private static RelyingParty build(RelyingPartyIdentity aIdentity, CredentialRepository aRepository, String aOrigin,
                                      AttestationConveyancePreference aAttestation) {
        return RelyingParty.builder()
                .identity(aIdentity)
                .credentialRepository(aRepository)
                .origins(Set.of(aOrigin))
                .allowOriginPort(false)
                .allowOriginSubdomain(false)
                .allowUntrustedAttestation(true)
                .validateSignatureCounter(false)
                .attestationConveyancePreference(aAttestation)
                .preferredPubkeyParams(ALGORITHMS)
                .build();
    }

    public RelyingParty get(String aOrigin, boolean aDirectAttestation) {
        RelyingParty rp = (aDirectAttestation ? direct : none).get(aOrigin);
        if (rp == null) {
            throw new IllegalArgumentException("Origin is not configured");
        }
        return rp;
    }
}
