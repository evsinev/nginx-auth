package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.policy.AccessChecker;
import com.payneteasy.nginxauth.policy.EffectivePolicy;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.PreAuth;
import com.payneteasy.nginxauth.webauthn.WebAuthnContext;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Optional;

/**
 * GET {@code <AUTH_URL>/verify}: second step after the password. Shows the security key prompt, the enrollment
 * secret form or the enrollment prompt, depending on the pending pre-authentication.
 */
public class VerifyPageServlet extends HttpServlet {

    private final WebAuthnWeb     web;
    private final WebAuthnContext webauthn;

    public VerifyPageServlet(AppContext aApp) {
        web = new WebAuthnWeb(aApp);
        webauthn = aApp.webauthn();
    }

    @Override
    protected void doGet(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        HttpRequestUtil.logDebug(aRequest);
        Optional<BrowserState> stateOpt = web.existingBinding(aRequest);
        long now = System.currentTimeMillis();
        PreAuth pre = stateOpt.map(BrowserState::preAuth).orElse(null);
        if (pre == null || !pre.isLive(now, webauthn.config().getPreauthTtlMillis())) {
            BrowserState state = stateOpt.isPresent() ? stateOpt.get() : web.ensureBinding(aRequest, aResponse).orElse(null);
            web.loginForm(aResponse, state, pre == null ? "/" : pre.back(), null, null, "Your login has expired. Please enter your password again.");
            return;
        }
        BrowserState state = stateOpt.get();

        if (pre.recoveryGrantId() != null) {
            web.ceremonyPage(aResponse, state, "recovery_enroll", "Register a new security key",
                    "Enrollment secret accepted. Register your new security key.", null, false, pre.back());
            return;
        }
        EffectivePolicy policy;
        try {
            policy = webauthn.resolver().resolve(pre.principal().getGroups(), pre.policyId());
        } catch (IllegalArgumentException e) {
            web.message(aResponse, HttpServletResponse.SC_FORBIDDEN, "Access denied", "Access denied by policy.", null, null);
            return;
        }
        boolean eligible = AccessChecker.hasEligible(webauthn.repository().find(pre.uid()).orElse(null), policy);
        if (!eligible || "1".equals(aRequest.getParameter("recovery"))) {
            web.ceremonyPage(aResponse, state, "recovery", "Security key required",
                    eligible ? "Enter the enrollment secret you received from your administrator."
                             : "Your account requires a security key, but none is registered. Enter the enrollment secret you received from your administrator.",
                    null, false, pre.back());
            return;
        }
        web.ceremonyPage(aResponse, state, "login", "Confirm with your security key",
                "Use your security key or passkey to finish logging in.", null, true, pre.back());
    }
}
