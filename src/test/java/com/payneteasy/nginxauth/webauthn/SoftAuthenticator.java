package com.payneteasy.nginxauth.webauthn;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.upokecenter.cbor.CBORObject;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

/**
 * Software WebAuthn authenticator for tests: ES256, attestation "none", configurable flags and counter.
 * Each mutator returns {@code this}; tamper switches affect the next response only.
 */
public final class SoftAuthenticator {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder D64 = Base64.getUrlDecoder();

    private final KeyPair keyPair;
    private final byte[]  credentialId;
    private final UUID    aaguid;

    public boolean backupEligible;
    public boolean backupState;
    public boolean userVerified = true;
    public long    signCount;
    public boolean crossOrigin;
    public String  rpIdOverride;
    public byte[]  userHandle;

    public SoftAuthenticator() {
        this(new UUID(0x0123456789abcdefL, 0x0fedcba987654321L));
    }

    public SoftAuthenticator(UUID aAaguid) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            keyPair = generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        credentialId = SecureTokens.randomBytes(32);
        aaguid = aAaguid;
    }

    public SoftAuthenticator copyWithSameCredentialId(SoftAuthenticator aOther) {
        System.arraycopy(aOther.credentialId, 0, credentialId, 0, credentialId.length);
        return this;
    }

    public String credentialId() {
        return B64.encodeToString(credentialId);
    }

    /** @param aOptionsJson output of toCredentialsCreateJson() */
    public String create(String aOptionsJson, String aOrigin) {
        JsonObject publicKey = JsonParser.parseString(aOptionsJson).getAsJsonObject().getAsJsonObject("publicKey");
        String rpId = rpIdOverride != null ? rpIdOverride : publicKey.getAsJsonObject("rp").get("id").getAsString();
        userHandle = D64.decode(publicKey.getAsJsonObject("user").get("id").getAsString());
        byte[] clientData = clientData("webauthn.create", publicKey.get("challenge").getAsString(), aOrigin);

        ByteArrayOutputStream authData = new ByteArrayOutputStream();
        authData.writeBytes(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
        authData.write(flags() | 0x40);
        authData.writeBytes(ByteBuffer.allocate(4).putInt((int) signCount).array());
        authData.writeBytes(ByteBuffer.allocate(16).putLong(aaguid.getMostSignificantBits()).putLong(aaguid.getLeastSignificantBits()).array());
        authData.writeBytes(ByteBuffer.allocate(2).putShort((short) credentialId.length).array());
        authData.writeBytes(credentialId);
        authData.writeBytes(coseKey());

        CBORObject attestation = CBORObject.NewMap();
        attestation.Add("fmt", "none");
        attestation.Add("attStmt", CBORObject.NewMap());
        attestation.Add("authData", authData.toByteArray());

        JsonObject response = new JsonObject();
        response.addProperty("clientDataJSON", B64.encodeToString(clientData));
        response.addProperty("attestationObject", B64.encodeToString(attestation.EncodeToBytes()));
        JsonArray transports = new JsonArray();
        transports.add("usb");
        response.add("transports", transports);
        crossOrigin = false;
        rpIdOverride = null;
        return credential(response);
    }

    /** @param aOptionsJson output of toCredentialsGetJson() */
    public String get(String aOptionsJson, String aOrigin) {
        JsonObject publicKey = JsonParser.parseString(aOptionsJson).getAsJsonObject().getAsJsonObject("publicKey");
        String rpId = rpIdOverride != null ? rpIdOverride : publicKey.get("rpId").getAsString();
        byte[] clientData = clientData("webauthn.get", publicKey.get("challenge").getAsString(), aOrigin);

        ByteArrayOutputStream authData = new ByteArrayOutputStream();
        authData.writeBytes(sha256(rpId.getBytes(StandardCharsets.UTF_8)));
        authData.write(flags());
        authData.writeBytes(ByteBuffer.allocate(4).putInt((int) signCount).array());
        byte[] authenticatorData = authData.toByteArray();

        byte[] signature;
        try {
            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(authenticatorData);
            signer.update(sha256(clientData));
            signature = signer.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        JsonObject response = new JsonObject();
        response.addProperty("clientDataJSON", B64.encodeToString(clientData));
        response.addProperty("authenticatorData", B64.encodeToString(authenticatorData));
        response.addProperty("signature", B64.encodeToString(signature));
        if (userHandle != null) {
            response.addProperty("userHandle", B64.encodeToString(userHandle));
        }
        crossOrigin = false;
        rpIdOverride = null;
        return credential(response);
    }

    private String credential(JsonObject aResponse) {
        JsonObject credential = new JsonObject();
        credential.addProperty("id", credentialId());
        credential.addProperty("rawId", credentialId());
        credential.addProperty("type", "public-key");
        credential.add("response", aResponse);
        credential.add("clientExtensionResults", new JsonObject());
        return credential.toString();
    }

    private byte[] clientData(String aType, String aChallenge, String aOrigin) {
        JsonObject clientData = new JsonObject();
        clientData.addProperty("type", aType);
        clientData.addProperty("challenge", aChallenge);
        clientData.addProperty("origin", aOrigin);
        clientData.addProperty("crossOrigin", crossOrigin);
        return clientData.toString().getBytes(StandardCharsets.UTF_8);
    }

    private int flags() {
        int flags = 0x01;
        if (userVerified) {
            flags |= 0x04;
        }
        if (backupEligible) {
            flags |= 0x08;
        }
        if (backupState) {
            flags |= 0x10;
        }
        return flags;
    }

    private byte[] coseKey() {
        ECPublicKey key = (ECPublicKey) keyPair.getPublic();
        CBORObject cose = CBORObject.NewMap();
        cose.Add(1, 2);
        cose.Add(3, -7);
        cose.Add(-1, 1);
        cose.Add(-2, unsigned32(key.getW().getAffineX()));
        cose.Add(-3, unsigned32(key.getW().getAffineY()));
        return cose.EncodeToBytes();
    }

    private static byte[] unsigned32(BigInteger aValue) {
        byte[] bytes = aValue.toByteArray();
        if (bytes.length == 32) {
            return bytes;
        }
        byte[] out = new byte[32];
        if (bytes.length > 32) {
            System.arraycopy(bytes, bytes.length - 32, out, 0, 32);
        } else {
            System.arraycopy(bytes, 0, out, 32 - bytes.length, bytes.length);
        }
        return out;
    }

    private static byte[] sha256(byte[] aData) {
        return SecureTokens.sha256(aData);
    }

    static byte[] copy(byte[] a) {
        return Arrays.copyOf(a, a.length);
    }
}
