package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.policy.AccessChecker;
import com.payneteasy.nginxauth.policy.PolicySet;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.util.BackUrl;
import com.payneteasy.nginxauth.util.CookiesManager;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.SettingsManager;
import com.payneteasy.nginxauth.webauthn.Audit;
import com.payneteasy.nginxauth.webauthn.WebAuthnContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

/**
 * Decision for a protected request. Without WebAuthn: a valid token is enough (as before). With WebAuthn:
 * the session is matched against the effective policy of the location on every request.
 */
final class AccessGate {

    private static final Logger LOG = LoggerFactory.getLogger(AccessGate.class);

    static final String LOGIN_CONTEXT_HEADER = "X-Login-Context";

    enum Outcome { ALLOW, LOGIN, FORBIDDEN }

    record Result(Outcome outcome, String contextId) {
    }

    private final AppContext app;

    AccessGate(AppContext aApp) {
        app = aApp;
    }

    /**
     * @param aBack the protected URL to return to after login, already taken from the request
     */
    Result evaluate(HttpServletRequest aRequest, HttpServletResponse aResponse, String aBack) {
        String token = new CookiesManager(aRequest, aResponse).getCookieValue(SettingsManager.getTokenCookieName());
        WebAuthnContext webauthn = app.webauthn();
        if (webauthn == null) {
            return new Result(app.tokens().validateToken(token) ? Outcome.ALLOW : Outcome.LOGIN, null);
        }

        String header = aRequest.getHeader(webauthn.config().getPolicyHeader());
        String policyId = header == null ? null : header.trim();
        if (!webauthn.resolver().isKnownPolicyId(policyId)) {
            LOG.error("Missing or unknown {} from nginx; check the nginx location config", webauthn.config().getPolicyHeader());
            Audit.log("access_denied_by_policy", "reason", "unknown_policy_id", "ip", HttpRequestUtil.clientIp(aRequest));
            return new Result(Outcome.FORBIDDEN, null);
        }
        if (policyId == null || policyId.isEmpty() || !webauthn.resolver().locationPoliciesEnabled()) {
            policyId = PolicySet.NONE_POLICY_ID;
        }

        Optional<Session> session = app.tokens().getSession(token).filter(webauthn.service()::isCurrent);
        if (session.isPresent()) {
            AccessChecker.Decision decision = webauthn.accessChecker().check(session.get(), policyId);
            if (decision == AccessChecker.Decision.ALLOW) {
                return new Result(Outcome.ALLOW, null);
            }
            Audit.log("access_denied_by_policy", "uid", session.get().getCanonicalUid(), "policyId", policyId,
                    "decision", decision.name().toLowerCase(), "method", session.get().getMethod().name());
        }

        String back = aBack == null ? null : BackUrl.normalize(aBack).orElse(null);
        String origin = webauthn.origins().resolve(aRequest).orElse(null);
        Optional<String> contextId = webauthn.contexts().create(policyId, back, origin);
        if (contextId.isEmpty()) {
            LOG.warn("Login context store is full");
        }
        // an empty header still makes nginx redirect with ctx=, which the login page rejects instead of
        // silently falling back to policyId=none
        aResponse.setHeader(LOGIN_CONTEXT_HEADER, contextId.orElse(""));
        return new Result(Outcome.LOGIN, contextId.orElse(""));
    }
}
