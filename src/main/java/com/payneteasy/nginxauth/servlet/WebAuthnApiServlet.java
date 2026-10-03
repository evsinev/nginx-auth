package com.payneteasy.nginxauth.servlet;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.webauthn.Audit;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.WebAuthnException;
import com.payneteasy.nginxauth.webauthn.WebAuthnService;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.Ceremony;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.Done;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.FinishResult;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.NextCeremony;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.SessionIssued;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

/**
 * POST {@code <AUTH_URL>/webauthn/start} and {@code /finish}. JSON in and out; requires the binding cookie,
 * the CSRF header and an exact Origin.
 */
public class WebAuthnApiServlet extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger(WebAuthnApiServlet.class);

    static final int MAX_BODY_BYTES = 64 * 1024;

    private final WebAuthnWeb     web;
    private final WebAuthnService service;

    public WebAuthnApiServlet(AppContext aApp) {
        web = new WebAuthnWeb(aApp);
        service = aApp.webauthn().service();
    }

    @Override
    protected void doPost(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        Optional<String> origin = web.postOrigin(aRequest);
        Optional<BrowserState> state = web.existingBinding(aRequest);
        if (origin.isEmpty() || state.isEmpty() || !web.checkCsrf(state.get(), aRequest.getHeader(WebAuthnWeb.CSRF_HEADER))) {
            Audit.log("csrf_rejected", "path", aRequest.getRequestURI(), "ip", HttpRequestUtil.clientIp(aRequest),
                    "reason", origin.isEmpty() ? "origin" : state.isEmpty() ? "binding" : "token");
            error(aResponse, HttpServletResponse.SC_FORBIDDEN, "Request rejected. Reload the page and try again.");
            return;
        }
        String contentType = aRequest.getContentType();
        if (contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("application/json")) {
            error(aResponse, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE, "Unsupported request");
            return;
        }
        JsonObject body;
        try {
            body = readBody(aRequest);
        } catch (IllegalArgumentException e) {
            error(aResponse, HttpServletResponse.SC_BAD_REQUEST, "Malformed request");
            return;
        }

        String action = aRequest.getPathInfo();
        String token = web.sessionToken(aRequest);
        try {
            if ("/start".equals(action)) {
                Ceremony ceremony = start(state.get(), origin.get(), token, body);
                JsonObject out = ok();
                out.add("ceremony", ceremonyJson(ceremony, string(body, "purpose")));
                json(aResponse, HttpServletResponse.SC_OK, out);
            } else if ("/finish".equals(action)) {
                JsonElement credential = body.get("credential");
                if (credential == null || !credential.isJsonObject()) {
                    error(aResponse, HttpServletResponse.SC_BAD_REQUEST, "Malformed request");
                    return;
                }
                FinishResult result = service.finish(state.get(), origin.get(), token, string(body, "purpose"),
                        string(body, "transactionId"), credential.toString(), string(body, "name"));
                JsonObject out = ok();
                if (result instanceof SessionIssued issued) {
                    WebAuthnWeb.issueSessionCookie(aRequest, aResponse, issued.token());
                    out.addProperty("redirect", issued.back());
                } else if (result instanceof NextCeremony next) {
                    out.add("ceremony", ceremonyJson(next.ceremony(), continuationPurpose(string(body, "purpose"))));
                } else if (result instanceof Done done) {
                    out.addProperty("message", done.message());
                    out.addProperty("redirect", WebAuthnWeb.AUTH_URL + "/credentials");
                }
                json(aResponse, HttpServletResponse.SC_OK, out);
            } else {
                error(aResponse, HttpServletResponse.SC_NOT_FOUND, "Not found");
            }
        } catch (WebAuthnException e) {
            LOG.info("WebAuthn {} rejected: {}", action, e.reason());
            error(aResponse, HttpServletResponse.SC_BAD_REQUEST, e.userMessage());
        }
    }

    private Ceremony start(BrowserState aState, String aOrigin, String aToken, JsonObject aBody) throws WebAuthnException {
        String purpose = string(aBody, "purpose");
        if (purpose == null) {
            throw new WebAuthnException("bad_purpose");
        }
        return switch (purpose) {
            case "login" -> service.startLogin(aState, aOrigin);
            case "recovery_enroll" -> service.startRecoveryEnroll(aState, aOrigin);
            case "step_up" -> service.startStepUp(aState, aOrigin, aToken, string(aBody, "contextId"));
            case "register" -> service.startRegister(aState, aOrigin, aToken);
            case "delete_credential" -> service.startDelete(aState, aOrigin, aToken, string(aBody, "credentialId"), bool(aBody, "confirmLast"));
            default -> throw new WebAuthnException("bad_purpose");
        };
    }

    /** register.confirm continues as register; recovery_enroll continues as login. */
    private static String continuationPurpose(String aPurpose) {
        return "recovery_enroll".equals(aPurpose) ? "login" : aPurpose;
    }

    private static JsonObject ceremonyJson(Ceremony aCeremony, String aPurpose) {
        JsonObject options = JsonParser.parseString(aCeremony.publicKeyJson()).getAsJsonObject();
        JsonObject ceremony = new JsonObject();
        ceremony.addProperty("transactionId", aCeremony.transactionId());
        ceremony.addProperty("type", aCeremony.type());
        ceremony.addProperty("purpose", aPurpose);
        ceremony.add("publicKey", options.get("publicKey"));
        return ceremony;
    }

    private static JsonObject readBody(HttpServletRequest aRequest) throws IOException {
        byte[] bytes;
        try (InputStream in = aRequest.getInputStream()) {
            bytes = in.readNBytes(MAX_BODY_BYTES + 1);
        }
        if (bytes.length > MAX_BODY_BYTES) {
            throw new IllegalArgumentException("body too large");
        }
        try {
            JsonElement element = JsonParser.parseString(new String(bytes, StandardCharsets.UTF_8));
            if (!element.isJsonObject()) {
                throw new IllegalArgumentException("not an object");
            }
            return element.getAsJsonObject();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("malformed");
        }
    }

    private static String string(JsonObject aObject, String aKey) {
        JsonElement value = aObject.get(aKey);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            return null;
        }
        return value.getAsString();
    }

    private static boolean bool(JsonObject aObject, String aKey) {
        JsonElement value = aObject.get(aKey);
        return value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isBoolean() && value.getAsBoolean();
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
        aResponse.setHeader("Cache-Control", "no-store");
        aResponse.setHeader("X-Content-Type-Options", "nosniff");
        aResponse.setContentType("application/json; charset=UTF-8");
        aResponse.getWriter().write(aBody.toString());
    }
}
