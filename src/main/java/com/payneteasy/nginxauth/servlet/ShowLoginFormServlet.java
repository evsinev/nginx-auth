package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.policy.AccessChecker;
import com.payneteasy.nginxauth.policy.EffectivePolicy;
import com.payneteasy.nginxauth.policy.PolicySet;
import com.payneteasy.nginxauth.service.INonceManager;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.util.*;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.LoginContextStore.LoginContext;
import com.payneteasy.nginxauth.webauthn.WebAuthnContext;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

import static com.payneteasy.nginxauth.util.SettingsManager.getTokenCookieAssignedName;
import static com.payneteasy.nginxauth.util.SettingsManager.getTokenCookieName;

public class ShowLoginFormServlet extends HttpServlet {

    private static final String BACK_URL_NAME = SettingsManager.getBackUrlName();

    public ShowLoginFormServlet(AppContext aApp) {
        theOtpEnabled   = aApp.otpEnabled();
        theNonceManager = aApp.nonces();
        theApp          = aApp;
        theWeb          = aApp.webauthn() == null ? null : new WebAuthnWeb(aApp);
    }

    @Override
    protected void doGet(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        HttpRequestUtil.logDebug(aRequest);
        HttpRequestUtil.setNoStoreHeaders(aResponse);

        if (theWeb != null) {
            doGetWebAuthn(aRequest, aResponse);
            return;
        }

        String backRaw = aRequest.getParameter(BACK_URL_NAME);

        VelocityBuilder velocity = new VelocityBuilder();
        velocity.add("FORM_ACTION", "/auth/login");
        velocity.add("BACK_URL_NAME",  BACK_URL_NAME);
        Optional<String> backOpt = BackUrl.normalize(backRaw);
        if (backOpt.isPresent() && !LoginFormServlet.tooLong(backRaw, LoginFormServlet.MAX_BACK)) {
            velocity.add("BACK_URL_VALUE", backOpt.get());
        } else {
            velocity.add("BACK_URL_VALUE", "");
            velocity.add("REASON", "Bad back url");
        }
        velocity.add("OTP_ENABLED" , theOtpEnabled             );

        CookiesManager cookiesManager = new CookiesManager(aRequest, aResponse);
        if(!cookiesManager.hasCookie(getTokenCookieName()) && cookiesManager.hasCookie(getTokenCookieAssignedName())) {
            velocity.add("REASON", "Please check secure cookie. Do not use http when secure cookies is enabled.");
        }
        LoginFormServlet.putNonce(velocity, theNonceManager);

        velocity.processTemplate(ShowLoginFormServlet.class, "/pages/login-form.vm", aResponse.getWriter());

    }

    private void doGetWebAuthn(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        WebAuthnContext webauthn = theWeb.webauthn();
        Optional<String> origin = theWeb.hostOrigin(aRequest);
        if (origin.isEmpty()) {
            theWeb.message(aResponse, HttpServletResponse.SC_FORBIDDEN, "Unknown host", "This host is not configured for login.", null, null);
            return;
        }
        Optional<BrowserState> stateOpt = theWeb.ensureBinding(aRequest, aResponse);
        if (stateOpt.isEmpty()) {
            theWeb.message(aResponse, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Service busy", "Service busy. Please try again later.", null, null);
            return;
        }
        BrowserState state = stateOpt.get();

        LoginContext context = null;
        if (WebAuthnWeb.hasParameter(aRequest, WebAuthnWeb.CONTEXT_PARAM)) {
            Optional<LoginContext> claimed = webauthn.contexts().claim(aRequest.getParameter(WebAuthnWeb.CONTEXT_PARAM), state.binding(), origin.get());
            if (claimed.isEmpty() || claimed.get().back() == null) {
                theWeb.message(aResponse, HttpServletResponse.SC_BAD_REQUEST, "Login link expired",
                        "The login link has expired. Open the protected page again.", "/", "Home");
                return;
            }
            context = claimed.get();
        }
        String back = context != null ? context.back() : WebAuthnLoginFlow.backFromParameter(aRequest);
        String contextId = context != null ? context.contextId() : null;
        String reason = back == null ? "Bad back url" : null;

        Optional<Session> session = theApp.tokens().peekSession(theWeb.sessionToken(aRequest));
        if (session.isPresent() && context != null) {
            String policyId = context.policyId();
            AccessChecker.Decision decision = webauthn.accessChecker().check(session.get(), policyId);
            if (decision == AccessChecker.Decision.ALLOW) {
                aResponse.sendRedirect(back);
                return;
            }
            if (decision == AccessChecker.Decision.STEP_UP && canStepUp(webauthn, session.get(), policyId)) {
                theWeb.ceremonyPage(aResponse, state, "step_up", "Confirm with your security key",
                        "This page requires a fresh confirmation with your security key.", contextId, false, back);
                return;
            }
            reason = "This page requires a stronger login. Please log in with your security key.";
        }

        CookiesManager cookies = new CookiesManager(aRequest, aResponse);
        if (!cookies.hasCookie(getTokenCookieName()) && cookies.hasCookie(getTokenCookieAssignedName())) {
            reason = "Please check secure cookie. Do not use http when secure cookies is enabled.";
        }
        theWeb.loginForm(aResponse, state, back == null ? "" : back, contextId, null, reason);
    }

    private static boolean canStepUp(WebAuthnContext aWebauthn, Session aSession, String aPolicyId) {
        if (!aWebauthn.service().isUsableFor(aSession.getCanonicalUid())) {
            return false;
        }
        EffectivePolicy policy = aWebauthn.resolver().resolve(aSession.getGroups(),
                aPolicyId == null ? PolicySet.NONE_POLICY_ID : aPolicyId);
        return AccessChecker.hasEligible(aWebauthn.repository().find(aSession.getCanonicalUid()).orElse(null), policy);
    }

    private final boolean       theOtpEnabled;
    private final INonceManager theNonceManager;
    private final AppContext    theApp;
    private final WebAuthnWeb   theWeb;

}
