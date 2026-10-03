package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.util.CookiesManager;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.SettingsManager;
import com.payneteasy.nginxauth.util.VelocityBuilder;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.WebAuthnContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

/**
 * Request plumbing shared by the WebAuthn-mode servlets: binding cookie, origin, CSRF, sessions, pages.
 */
final class WebAuthnWeb {

    static final String AUTH_URL      = SettingsManager.getAuthUrl();
    static final String BACK_URL_NAME = SettingsManager.getBackUrlName();
    static final String CSRF_PARAM    = "j_csrf";
    static final String CSRF_HEADER   = "X-CSRF-Token";
    static final String CONTEXT_PARAM = "ctx";

    private final AppContext      app;
    private final WebAuthnContext webauthn;

    WebAuthnWeb(AppContext aApp) {
        app = aApp;
        webauthn = aApp.webauthn();
    }

    WebAuthnContext webauthn() {
        return webauthn;
    }

    AppContext app() {
        return app;
    }

    /** Existing browser state or a new one with a fresh binding cookie. Empty when the store is full. */
    Optional<BrowserState> ensureBinding(HttpServletRequest aRequest, HttpServletResponse aResponse) {
        CookiesManager cookies = new CookiesManager(aRequest, aResponse);
        String current = cookies.getCookieValue(BrowserStateStore.COOKIE_NAME);
        Optional<BrowserState> existing = webauthn.states().get(current);
        if (existing.isPresent()) {
            return existing;
        }
        Optional<BrowserState> created = webauthn.states().getOrCreate(null);
        created.ifPresent(state -> cookies.addBinding(BrowserStateStore.COOKIE_NAME, state.binding(), AUTH_URL));
        return created;
    }

    Optional<BrowserState> existingBinding(HttpServletRequest aRequest) {
        String current = new CookiesManager(aRequest, null).getCookieValue(BrowserStateStore.COOKIE_NAME);
        return webauthn.states().get(current);
    }

    /** Origin of the served host for a GET (no Origin header check). */
    Optional<String> hostOrigin(HttpServletRequest aRequest) {
        return webauthn.origins().resolve(aRequest);
    }

    /** Origin of a browser POST: Host allowed and Origin header exactly equal. */
    Optional<String> postOrigin(HttpServletRequest aRequest) {
        return webauthn.origins().checkPost(aRequest);
    }

    boolean checkCsrf(BrowserState aState, String aToken) {
        return webauthn.states().checkCsrf(aState, aToken);
    }

    String sessionToken(HttpServletRequest aRequest) {
        return new CookiesManager(aRequest, null).getCookieValue(SettingsManager.getTokenCookieName());
    }

    static void issueSessionCookie(HttpServletRequest aRequest, HttpServletResponse aResponse, String aToken) {
        CookiesManager cookies = new CookiesManager(aRequest, aResponse);
        cookies.add(SettingsManager.getTokenCookieName(), aToken);
        cookies.addAssignedMarker(SettingsManager.getTokenCookieAssignedName(), System.currentTimeMillis() + "");
    }

    static boolean hasParameter(HttpServletRequest aRequest, String aName) {
        Map<String, String[]> parameters = aRequest.getParameterMap();
        return parameters.containsKey(aName);
    }

    // ------------------------------------------------------------------ pages

    VelocityBuilder page(BrowserState aState) {
        VelocityBuilder velocity = new VelocityBuilder();
        velocity.add("AUTH_URL", AUTH_URL);
        velocity.add("BACK_URL_NAME", BACK_URL_NAME);
        velocity.add("OTP_ENABLED", app.otpEnabled());
        velocity.add("WEBAUTHN", Boolean.TRUE);
        if (aState != null) {
            velocity.add("CSRF", aState.csrfToken());
        }
        return velocity;
    }

    void render(HttpServletResponse aResponse, VelocityBuilder aVelocity, String aTemplate) throws IOException {
        HttpRequestUtil.setNoStoreHeaders(aResponse);
        aVelocity.processTemplate(WebAuthnWeb.class, aTemplate, aResponse.getWriter());
    }

    void loginForm(HttpServletResponse aResponse, BrowserState aState, String aBack, String aContextId, String aUsername,
                   String aReason) throws IOException {
        VelocityBuilder velocity = page(aState);
        velocity.add("FORM_ACTION", AUTH_URL + "/login");
        velocity.add("BACK_URL_VALUE", aBack == null ? "" : aBack);
        if (aContextId != null) {
            velocity.add("CTX", aContextId);
        }
        velocity.add("USERNAME", aUsername);
        velocity.add("REASON", aReason);
        velocity.add("NONCE", "");
        render(aResponse, velocity, "/pages/login-form.vm");
    }

    void changePasswordForm(HttpServletResponse aResponse, BrowserState aState, String aBack, String aContextId, String aUsername,
                            String aReason) throws IOException {
        VelocityBuilder velocity = page(aState);
        velocity.add("BACK_URL_VALUE", aBack == null ? "" : aBack);
        if (aContextId != null) {
            velocity.add("CTX", aContextId);
        }
        velocity.add("USERNAME", aUsername);
        velocity.add("REASON", aReason);
        velocity.add("NONCE", "");
        render(aResponse, velocity, "/pages/change-password-form.vm");
    }

    void message(HttpServletResponse aResponse, int aStatus, String aTitle, String aMessage, String aLink, String aLinkText) throws IOException {
        aResponse.setStatus(aStatus);
        VelocityBuilder velocity = page(null);
        velocity.add("TITLE", aTitle);
        velocity.add("MESSAGE", aMessage);
        velocity.add("LINK", aLink);
        velocity.add("LINK_TEXT", aLinkText);
        render(aResponse, velocity, "/pages/message.vm");
    }

    void ceremonyPage(HttpServletResponse aResponse, BrowserState aState, String aMode, String aTitle, String aMessage,
                      String aContextId, boolean aShowRecoveryLink, String aBack) throws IOException {
        VelocityBuilder velocity = page(aState);
        velocity.add("MODE", aMode);
        velocity.add("TITLE", aTitle);
        velocity.add("MESSAGE", aMessage);
        velocity.add("CTX", aContextId == null ? "" : aContextId);
        velocity.add("SHOW_RECOVERY", aShowRecoveryLink);
        velocity.add("BACK_ENCODED", URLEncoder.encode(aBack == null ? "/" : aBack, StandardCharsets.UTF_8));
        render(aResponse, velocity, "/pages/webauthn.vm");
    }
}
