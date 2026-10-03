package com.payneteasy.nginxauth.webauthn.storage;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Strict JSON mapping for {@link UserRecord}. Unknown keys and malformed values are rejected.
 */
public final class UserRecordCodec {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();

    private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");

    private static final Set<String> ROOT_KEYS       = Set.of("version", "uid", "userHandle", "enrollmentGrant", "credentials");
    private static final Set<String> GRANT_KEYS      = Set.of("grantId", "secretHash", "expiresAt", "usesLeft", "issuedBy", "issuedAt");
    private static final Set<String> CREDENTIAL_KEYS = Set.of("credentialId", "publicKeyCose", "signCount", "aaguid", "backupEligible",
            "backupState", "transports", "name", "createdAt", "lastUsedAt");

    private UserRecordCodec() {
    }

    public static byte[] encode(UserRecord aRecord) {
        JsonObject root = new JsonObject();
        root.addProperty("version", UserRecord.VERSION);
        root.addProperty("uid", aRecord.uid());
        root.addProperty("userHandle", aRecord.userHandle());
        EnrollmentGrant grant = aRecord.enrollmentGrant();
        if (grant != null) {
            JsonObject g = new JsonObject();
            g.addProperty("grantId", grant.grantId());
            g.addProperty("secretHash", grant.secretHash());
            g.addProperty("expiresAt", Instant.ofEpochMilli(grant.expiresAt()).toString());
            g.addProperty("usesLeft", grant.usesLeft());
            g.addProperty("issuedBy", grant.issuedBy());
            g.addProperty("issuedAt", Instant.ofEpochMilli(grant.issuedAt()).toString());
            root.add("enrollmentGrant", g);
        }
        JsonArray credentials = new JsonArray();
        for (StoredCredential credential : aRecord.credentials()) {
            JsonObject c = new JsonObject();
            c.addProperty("credentialId", credential.credentialId());
            c.addProperty("publicKeyCose", credential.publicKeyCose());
            c.addProperty("signCount", credential.signCount());
            c.addProperty("aaguid", credential.aaguid());
            c.addProperty("backupEligible", credential.backupEligible());
            c.addProperty("backupState", credential.backupState());
            JsonArray transports = new JsonArray();
            credential.transports().forEach(transports::add);
            c.add("transports", transports);
            c.addProperty("name", credential.name());
            c.addProperty("createdAt", Instant.ofEpochMilli(credential.createdAt()).toString());
            if (credential.lastUsedAt() == 0L) {
                c.add("lastUsedAt", JsonNull.INSTANCE);
            } else {
                c.addProperty("lastUsedAt", Instant.ofEpochMilli(credential.lastUsedAt()).toString());
            }
            credentials.add(c);
        }
        root.add("credentials", credentials);
        return GSON.toJson(root).getBytes(StandardCharsets.UTF_8);
    }

    public static UserRecord decode(byte[] aBytes) {
        JsonElement element;
        try {
            element = JsonParser.parseString(new String(aBytes, StandardCharsets.UTF_8));
        } catch (JsonParseException e) {
            throw new IllegalArgumentException("not valid JSON");
        }
        JsonObject root = object(element, "root");
        checkKeys(root, ROOT_KEYS, "root");
        if (number(root, "version") != UserRecord.VERSION) {
            throw new IllegalArgumentException("unsupported version");
        }
        String uid = string(root, "uid");
        String userHandle = base64url(root, "userHandle");

        EnrollmentGrant grant = null;
        JsonElement grantElement = root.get("enrollmentGrant");
        if (grantElement != null && !grantElement.isJsonNull()) {
            JsonObject g = object(grantElement, "enrollmentGrant");
            checkKeys(g, GRANT_KEYS, "enrollmentGrant");
            long usesLeft = number(g, "usesLeft");
            if (usesLeft < 0 || usesLeft > 1000) {
                throw new IllegalArgumentException("enrollmentGrant.usesLeft out of range");
            }
            grant = new EnrollmentGrant(
                    string(g, "grantId"),
                    base64url(g, "secretHash"),
                    instant(g, "expiresAt"),
                    (int) usesLeft,
                    string(g, "issuedBy"),
                    instant(g, "issuedAt"));
        }

        List<StoredCredential> credentials = new ArrayList<>();
        JsonElement credentialsElement = root.get("credentials");
        if (credentialsElement == null || !credentialsElement.isJsonArray()) {
            throw new IllegalArgumentException("credentials must be an array");
        }
        for (JsonElement item : credentialsElement.getAsJsonArray()) {
            JsonObject c = object(item, "credential");
            checkKeys(c, CREDENTIAL_KEYS, "credential");
            List<String> transports = new ArrayList<>();
            JsonElement transportsElement = c.get("transports");
            if (transportsElement == null || !transportsElement.isJsonArray()) {
                throw new IllegalArgumentException("credential.transports must be an array");
            }
            for (JsonElement transport : transportsElement.getAsJsonArray()) {
                if (!transport.isJsonPrimitive() || !transport.getAsJsonPrimitive().isString()) {
                    throw new IllegalArgumentException("credential.transports must contain strings");
                }
                transports.add(transport.getAsString());
            }
            long signCount = number(c, "signCount");
            if (signCount < 0 || signCount > 0xFFFFFFFFL) {
                throw new IllegalArgumentException("credential.signCount out of range");
            }
            String aaguid = string(c, "aaguid");
            try {
                UUID.fromString(aaguid);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("credential.aaguid is invalid");
            }
            JsonElement lastUsed = c.get("lastUsedAt");
            credentials.add(new StoredCredential(
                    base64url(c, "credentialId"),
                    base64url(c, "publicKeyCose"),
                    signCount,
                    aaguid,
                    bool(c, "backupEligible"),
                    bool(c, "backupState"),
                    transports,
                    string(c, "name"),
                    instant(c, "createdAt"),
                    lastUsed == null || lastUsed.isJsonNull() ? 0L : instant(c, "lastUsedAt")));
        }
        return new UserRecord(uid, userHandle, grant, credentials);
    }

    private static JsonObject object(JsonElement aElement, String aPath) {
        if (aElement == null || !aElement.isJsonObject()) {
            throw new IllegalArgumentException(aPath + " must be an object");
        }
        return aElement.getAsJsonObject();
    }

    private static void checkKeys(JsonObject aObject, Set<String> aAllowed, String aPath) {
        for (String key : aObject.keySet()) {
            if (!aAllowed.contains(key)) {
                throw new IllegalArgumentException("unknown key " + aPath + "." + key);
            }
        }
    }

    private static String string(JsonObject aObject, String aKey) {
        JsonElement value = aObject.get(aKey);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(aKey + " must be a string");
        }
        return value.getAsString();
    }

    private static String base64url(JsonObject aObject, String aKey) {
        String value = string(aObject, aKey);
        if (!BASE64URL.matcher(value).matches()) {
            throw new IllegalArgumentException(aKey + " must be base64url without padding");
        }
        try {
            Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(aKey + " must be base64url without padding");
        }
        return value;
    }

    private static long number(JsonObject aObject, String aKey) {
        JsonElement value = aObject.get(aKey);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) {
            throw new IllegalArgumentException(aKey + " must be a number");
        }
        double d = value.getAsDouble();
        long l = value.getAsLong();
        if (d != l) {
            throw new IllegalArgumentException(aKey + " must be an integer");
        }
        return l;
    }

    private static boolean bool(JsonObject aObject, String aKey) {
        JsonElement value = aObject.get(aKey);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isBoolean()) {
            throw new IllegalArgumentException(aKey + " must be a boolean");
        }
        return value.getAsBoolean();
    }

    private static long instant(JsonObject aObject, String aKey) {
        try {
            return Instant.parse(string(aObject, aKey)).toEpochMilli();
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(aKey + " must be an ISO-8601 instant");
        }
    }
}
