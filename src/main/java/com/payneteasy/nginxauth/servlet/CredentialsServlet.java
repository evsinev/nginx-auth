package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.StringUtils;
import com.payneteasy.nginxauth.util.VelocityBuilder;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.WebAuthnContext;
import com.payneteasy.nginxauth.webauthn.storage.StoredCredential;
import com.payneteasy.nginxauth.webauthn.storage.UserRecord;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * GET {@code <AUTH_URL>/credentials}: the user's security keys, add and remove.
 */
public class CredentialsServlet extends HttpServlet {

    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    private final AppContext      app;
    private final WebAuthnWeb     web;
    private final WebAuthnContext webauthn;

    public CredentialsServlet(AppContext aApp) {
        app = aApp;
        web = new WebAuthnWeb(aApp);
        webauthn = aApp.webauthn();
    }

    @Override
    protected void doGet(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        HttpRequestUtil.logDebug(aRequest);
        Optional<Session> session = app.tokens().getSession(web.sessionToken(aRequest));
        if (session.isEmpty() || !webauthn.accessChecker().isSessionCredentialValid(session.get())) {
            aResponse.sendRedirect(WebAuthnWeb.AUTH_URL + "?" + WebAuthnWeb.BACK_URL_NAME + "="
                    + URLEncoder.encode(WebAuthnWeb.AUTH_URL + "/credentials", StandardCharsets.UTF_8));
            return;
        }
        Optional<BrowserState> state = web.ensureBinding(aRequest, aResponse);
        if (state.isEmpty()) {
            web.message(aResponse, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Service busy", "Service busy. Please try again later.", null, null);
            return;
        }
        String uid = session.get().getCanonicalUid();
        UserRecord record = webauthn.service().isUsableFor(uid) ? webauthn.repository().find(uid).orElse(null) : null;

        // values are escaped here: VelocityBuilder escapes only strings passed directly
        List<Map<String, String>> rows = new ArrayList<>();
        if (record != null) {
            for (StoredCredential credential : record.credentials()) {
                Map<String, String> row = new LinkedHashMap<>();
                row.put("id", StringUtils.escapeHtml(credential.credentialId()));
                row.put("name", StringUtils.escapeHtml(credential.name()));
                row.put("created", TIME.format(Instant.ofEpochMilli(credential.createdAt())));
                row.put("lastUsed", credential.lastUsedAt() == 0L ? "never" : TIME.format(Instant.ofEpochMilli(credential.lastUsedAt())));
                row.put("kind", credential.backupEligible() ? "multi-device" : "single-device");
                row.put("aaguid", StringUtils.escapeHtml(credential.aaguid()));
                row.put("current", credential.credentialId().equals(session.get().getCredentialId()) ? "yes" : "");
                rows.add(row);
            }
        }
        VelocityBuilder velocity = web.page(state.get());
        velocity.add("USER", uid);
        velocity.add("METHOD", session.get().getMethod().name());
        velocity.add("CREDENTIALS", rows);
        velocity.add("AVAILABLE", webauthn.service().isUsableFor(uid));
        velocity.add("LAST_ONE", rows.size() == 1);
        web.render(aResponse, velocity, "/pages/credentials.vm");
    }
}
