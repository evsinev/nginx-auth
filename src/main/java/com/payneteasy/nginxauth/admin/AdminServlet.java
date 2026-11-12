package com.payneteasy.nginxauth.admin;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.payneteasy.nginxauth.webauthn.Audit;
import com.payneteasy.nginxauth.webauthn.SecureTokens;
import com.payneteasy.nginxauth.webauthn.WebAuthnContext;
import com.payneteasy.nginxauth.webauthn.WebAuthnException;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.GrantSpec;
import com.payneteasy.nginxauth.webauthn.storage.EnrollmentGrant;
import com.payneteasy.nginxauth.webauthn.storage.FileCredentialRepository;
import com.payneteasy.nginxauth.webauthn.storage.StoredCredential;
import com.payneteasy.nginxauth.webauthn.storage.UserRecord;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;

/**
 * Admin API on the loopback-only admin connector. Authenticated by WEBAUTHN_ADMIN_TOKEN only.
 */
public class AdminServlet extends HttpServlet {

    static final int MAX_BODY_BYTES = 8 * 1024;
    static final int MAX_TTL_HOURS  = 24 * 30;
    static final int MAX_USES       = 10;

    private final WebAuthnContext webauthn;
    private final String          expectedAuthorization;

    public AdminServlet(WebAuthnContext aWebauthn) {
        webauthn = aWebauthn;
        expectedAuthorization = "Bearer " + aWebauthn.config().getAdminToken();
    }

    @Override
    protected void service(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        aResponse.setHeader("Cache-Control", "no-store");
        if (!SecureTokens.constantTimeEquals(expectedAuthorization, aRequest.getHeader("Authorization"))) {
            Audit.log("admin_auth_failed", "path", aRequest.getRequestURI(), "ip", aRequest.getRemoteAddr());
            error(aResponse, HttpServletResponse.SC_UNAUTHORIZED, "unauthorized");
            return;
        }
        String path = aRequest.getPathInfo();
        try {
            if ("POST".equals(aRequest.getMethod()) && "/reset".equals(path)) {
                JsonObject body = body(aRequest);
                String uid = uid(string(body, "uid"));
                GrantSpec grant = Boolean.TRUE.equals(bool(body, "grant")) ? grantSpec(body) : null;
                Optional<String> secret = webauthn.service().adminReset(uid, grant);
                JsonObject out = ok();
                secret.ifPresent(s -> out.addProperty("secret", s));
                json(aResponse, HttpServletResponse.SC_OK, out);
            } else if ("POST".equals(aRequest.getMethod()) && "/grant".equals(path)) {
                JsonObject body = body(aRequest);
                String uid = uid(string(body, "uid"));
                String secret = webauthn.service().adminIssueGrant(uid, grantSpec(body));
                JsonObject out = ok();
                out.addProperty("secret", secret);
                json(aResponse, HttpServletResponse.SC_OK, out);
            } else if ("GET".equals(aRequest.getMethod()) && "/user".equals(path)) {
                String uid = uid(aRequest.getParameter("uid"));
                json(aResponse, HttpServletResponse.SC_OK, show(uid));
            } else {
                error(aResponse, HttpServletResponse.SC_NOT_FOUND, "not found");
            }
        } catch (IllegalArgumentException e) {
            error(aResponse, HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
        } catch (WebAuthnException e) {
            error(aResponse, HttpServletResponse.SC_BAD_REQUEST, e.reason());
        }
    }

    private JsonObject show(String aUid) {
        JsonObject out = ok();
        out.addProperty("uid", aUid);
        Optional<UserRecord> record = webauthn.repository().find(aUid);
        JsonArray credentials = new JsonArray();
        if (record.isPresent()) {
            for (StoredCredential credential : record.get().credentials()) {
                JsonObject c = new JsonObject();
                c.addProperty("credential", Audit.cred(credential.credentialId()));
                c.addProperty("name", credential.name());
                c.addProperty("aaguid", credential.aaguid());
                c.addProperty("kind", credential.backupEligible() ? "multi-device" : "single-device");
                c.addProperty("createdAt", Instant.ofEpochMilli(credential.createdAt()).toString());
                c.addProperty("lastUsedAt", credential.lastUsedAt() == 0L ? null : Instant.ofEpochMilli(credential.lastUsedAt()).toString());
                credentials.add(c);
            }
            EnrollmentGrant grant = record.get().enrollmentGrant();
            if (grant != null) {
                JsonObject g = new JsonObject();
                g.addProperty("grantId", grant.grantId());
                g.addProperty("expiresAt", Instant.ofEpochMilli(grant.expiresAt()).toString());
                g.addProperty("usesLeft", grant.usesLeft());
                g.addProperty("issuedBy", grant.issuedBy());
                out.add("enrollmentGrant", g);
            }
        }
        out.add("credentials", credentials);
        return out;
    }

    private static GrantSpec grantSpec(JsonObject aBody) {
        long ttlHours = number(aBody, "ttlHours", 24);
        long uses = number(aBody, "uses", 1);
        if (ttlHours < 1 || ttlHours > MAX_TTL_HOURS) {
            throw new IllegalArgumentException("ttlHours must be 1.." + MAX_TTL_HOURS);
        }
        if (uses < 1 || uses > MAX_USES) {
            throw new IllegalArgumentException("uses must be 1.." + MAX_USES);
        }
        String issuedBy = string(aBody, "issuedBy");
        if (issuedBy == null || issuedBy.isBlank() || issuedBy.length() > 128) {
            throw new IllegalArgumentException("issuedBy is required");
        }
        return new GrantSpec(ttlHours, (int) uses, issuedBy);
    }

    private static String uid(String aUid) {
        if (!FileCredentialRepository.isValidUid(aUid)) {
            throw new IllegalArgumentException("invalid uid");
        }
        return aUid;
    }

    private static JsonObject body(HttpServletRequest aRequest) throws IOException {
        byte[] bytes;
        try (InputStream in = aRequest.getInputStream()) {
            bytes = in.readNBytes(MAX_BODY_BYTES + 1);
        }
        if (bytes.length > MAX_BODY_BYTES) {
            throw new IllegalArgumentException("body too large");
        }
        try {
            return JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8)).getAsJsonObject();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("malformed JSON");
        }
    }

    private static String string(JsonObject aObject, String aKey) {
        JsonElement value = aObject.get(aKey);
        return value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isString() ? value.getAsString() : null;
    }

    private static Boolean bool(JsonObject aObject, String aKey) {
        JsonElement value = aObject.get(aKey);
        return value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isBoolean() ? value.getAsBoolean() : null;
    }

    private static long number(JsonObject aObject, String aKey, long aDefault) {
        JsonElement value = aObject.get(aKey);
        if (value == null) {
            return aDefault;
        }
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber() || value.getAsDouble() != value.getAsLong()) {
            throw new IllegalArgumentException(aKey + " must be an integer");
        }
        return value.getAsLong();
    }

    private static JsonObject ok() {
        JsonObject out = new JsonObject();
        out.addProperty("ok", true);
        return out;
    }

    private static void error(HttpServletResponse aResponse, int aStatus, String aMessage) throws IOException {
        JsonObject out = new JsonObject();
        out.addProperty("ok", false);
        out.addProperty("error", aMessage);
        json(aResponse, aStatus, out);
    }

    private static void json(HttpServletResponse aResponse, int aStatus, JsonObject aBody) throws IOException {
        aResponse.setStatus(aStatus);
        aResponse.setContentType("application/json; charset=UTF-8");
        aResponse.getWriter().write(aBody.toString());
    }
}
