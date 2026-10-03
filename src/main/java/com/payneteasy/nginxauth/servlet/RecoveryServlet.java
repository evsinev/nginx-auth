package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.webauthn.Audit;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.PreAuth;
import com.payneteasy.nginxauth.webauthn.WebAuthnException;
import com.payneteasy.nginxauth.webauthn.WebAuthnService;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Optional;

/**
 * POST {@code <AUTH_URL>/recovery}: checks the enrollment secret for the pending pre-authentication.
 */
public class RecoveryServlet extends HttpServlet {

    static final int MAX_SECRET = 128;

    private final WebAuthnWeb     web;
    private final WebAuthnService service;

    public RecoveryServlet(AppContext aApp) {
        web = new WebAuthnWeb(aApp);
        service = aApp.webauthn().service();
    }

    @Override
    protected void doPost(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        HttpRequestUtil.logDebug(aRequest);
        Optional<BrowserState> state = web.existingBinding(aRequest);
        if (web.postOrigin(aRequest).isEmpty() || state.isEmpty()
                || !web.checkCsrf(state.get(), aRequest.getParameter(WebAuthnWeb.CSRF_PARAM))) {
            Audit.log("csrf_rejected", "path", aRequest.getRequestURI(), "ip", HttpRequestUtil.clientIp(aRequest));
            web.message(aResponse, HttpServletResponse.SC_FORBIDDEN, "Request rejected", "The request did not come from this site.", WebAuthnWeb.AUTH_URL, "Back to login");
            return;
        }
        PreAuth pre = state.get().preAuth();
        String back = pre == null ? "/" : pre.back();
        String secret = aRequest.getParameter("j_secret");
        try {
            if (secret != null && secret.length() <= MAX_SECRET && service.verifyRecoverySecret(state.get(), secret)) {
                aResponse.setStatus(HttpServletResponse.SC_SEE_OTHER);
                aResponse.setHeader("Location", WebAuthnWeb.AUTH_URL + "/verify");
                return;
            }
            if (pre != null && (secret == null || secret.length() > MAX_SECRET)) {
                web.webauthn().states().clearPreAuth(state.get(), pre.preauthId());
            }
            web.loginForm(aResponse, state.get(), back, null, null, "Invalid enrollment secret. Please log in again.");
        } catch (WebAuthnException e) {
            web.loginForm(aResponse, state.get(), back, null, null, e.userMessage());
        }
    }
}
