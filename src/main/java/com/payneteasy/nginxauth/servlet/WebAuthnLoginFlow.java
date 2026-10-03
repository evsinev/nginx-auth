package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.ldap.LdapPrincipal;
import com.payneteasy.nginxauth.policy.AccessChecker;
import com.payneteasy.nginxauth.policy.EffectivePolicy;
import com.payneteasy.nginxauth.policy.PolicySet;
import com.payneteasy.nginxauth.service.AuthenticationMethod;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.service.UserMustChangePasswordException;
import com.payneteasy.nginxauth.service.impl.RateLimiter;
import com.payneteasy.nginxauth.util.BackUrl;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.LoginAttempts;
import com.payneteasy.nginxauth.util.StringUtils;
import com.payneteasy.nginxauth.webauthn.Audit;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.LoginContextStore.LoginContext;
import com.payneteasy.nginxauth.webauthn.MethodSelector;
import com.payneteasy.nginxauth.webauthn.PreAuth;
import com.payneteasy.nginxauth.webauthn.WebAuthnContext;
import com.payneteasy.nginxauth.webauthn.storage.FileCredentialRepository;
import com.payneteasy.nginxauth.webauthn.storage.UserRecord;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.util.Optional;

import static com.payneteasy.nginxauth.servlet.LoginFormServlet.MAX_BACK;
import static com.payneteasy.nginxauth.servlet.LoginFormServlet.MAX_OTP;
import static com.payneteasy.nginxauth.servlet.LoginFormServlet.MAX_PASSWORD;
import static com.payneteasy.nginxauth.servlet.LoginFormServlet.MAX_USERNAME;
import static com.payneteasy.nginxauth.servlet.LoginFormServlet.tooLong;

/**
 * POST /auth/login and /auth/change-password with WebAuthn enabled: LDAP first, then the second factor chosen
 * by {@link MethodSelector}. No path issues a session without the factor the policy requires.
 */
final class WebAuthnLoginFlow {

    private static final Logger LOG = LoggerFactory.getLogger(WebAuthnLoginFlow.class);

    private final WebAuthnWeb     web;
    private final AppContext      app;
    private final WebAuthnContext webauthn;

    WebAuthnLoginFlow(WebAuthnWeb aWeb) {
        web = aWeb;
        app = aWeb.app();
        webauthn = aWeb.webauthn();
    }

    void handle(HttpServletRequest aRequest, HttpServletResponse aResponse, boolean aChangePassword) throws IOException {
        HttpRequestUtil.logDebug(aRequest);

        Optional<String> origin = web.postOrigin(aRequest);
        if (origin.isEmpty()) {
            Audit.log("csrf_rejected", "reason", "origin", "path", aRequest.getRequestURI(), "ip", HttpRequestUtil.clientIp(aRequest));
            web.message(aResponse, HttpServletResponse.SC_FORBIDDEN, "Request rejected", "The request did not come from this site.", WebAuthnWeb.AUTH_URL, "Back to login");
            return;
        }
        Optional<BrowserState> stateOpt = web.existingBinding(aRequest);
        if (stateOpt.isEmpty()) {
            BrowserState fresh = web.ensureBinding(aRequest, aResponse).orElse(null);
            web.loginForm(aResponse, fresh, backFromParameter(aRequest), null, null, fresh == null ? "Service busy" : "Your login page has expired. Please try again.");
            return;
        }
        BrowserState state = stateOpt.get();
        long generation = state.generation();
        if (!web.checkCsrf(state, aRequest.getParameter(WebAuthnWeb.CSRF_PARAM))) {
            Audit.log("csrf_rejected", "reason", "token", "path", aRequest.getRequestURI(), "ip", HttpRequestUtil.clientIp(aRequest));
            web.loginForm(aResponse, state, backFromParameter(aRequest), null, null, "Your login page has expired. Please try again.");
            return;
        }

        String contextId = null;
        String policyId = PolicySet.NONE_POLICY_ID;
        String back;
        if (WebAuthnWeb.hasParameter(aRequest, WebAuthnWeb.CONTEXT_PARAM)) {
            Optional<LoginContext> context = webauthn.contexts().claim(aRequest.getParameter(WebAuthnWeb.CONTEXT_PARAM), state.binding(), origin.get());
            if (context.isEmpty() || context.get().back() == null) {
                web.message(aResponse, HttpServletResponse.SC_BAD_REQUEST, "Login link expired",
                        "The login link has expired. Open the protected page again.", "/", "Home");
                return;
            }
            contextId = context.get().contextId();
            policyId = context.get().policyId();
            back = context.get().back();
        } else {
            // direct login without a back parameter returns to the site root
            back = WebAuthnWeb.hasParameter(aRequest, WebAuthnWeb.BACK_URL_NAME) ? backFromParameter(aRequest) : "/";
            if (back == null) {
                web.loginForm(aResponse, state, "", null, null, "Bad back url");
                return;
            }
        }

        String username = aRequest.getParameter("j_username");
        String password = aRequest.getParameter("j_password");
        String otp      = aRequest.getParameter("j_code");

        if (tooLong(username, MAX_USERNAME) || StringUtils.isEmpty(username)) {
            form(aResponse, aChangePassword, state, back, contextId, "", StringUtils.isEmpty(username) ? "Username is empty" : "Username is too long");
            return;
        }
        if (tooLong(password, MAX_PASSWORD) || StringUtils.isEmpty(password)) {
            form(aResponse, aChangePassword, state, back, contextId, username, StringUtils.isEmpty(password) ? "Password is empty" : "Password is too long");
            return;
        }
        if (tooLong(otp, MAX_OTP)) {
            form(aResponse, aChangePassword, state, back, contextId, username, "Verification code is invalid");
            return;
        }
        boolean codeProvided = app.otpEnabled() && StringUtils.hasText(otp);

        RateLimiter.Attempt attempt = LoginAttempts.begin(aRequest, username);
        attempt.awaitDelay();
        if (attempt.denied()) {
            LOG.warn("Login throttled [user:{}]", username);
            form(aResponse, aChangePassword, state, back, contextId, username, "Authentication failed");
            return;
        }

        // read before any bind: a password change after this point makes this request unable to publish
        long loginGeneration = webauthn.service().loginGeneration(username);
        LdapPrincipal principal;
        boolean totpVerified = false;
        try {
            if (aChangePassword) {
                String newPassword = aRequest.getParameter("j_password_new_1");
                String repeated    = aRequest.getParameter("j_password_new_2");
                String problem = newPasswordProblem(newPassword, repeated);
                if (problem != null) {
                    web.changePasswordForm(aResponse, state, back, contextId, username, problem);
                    return;
                }
                String knownUid = null;
                try {
                    knownUid = app.authService().authenticatePrincipal(username, password).getCanonicalUid();
                } catch (UserMustChangePasswordException e) {
                    // expired password: the directory lets us read the principal only after the change
                    app.authService().authenticate(username, password, false);
                }
                if (codeProvided) {
                    if (!app.otpService().checkCode(username, parseCode(otp))) {
                        throw new AuthenticationException("Authentication failed");
                    }
                    totpVerified = true;
                } else if (app.otpEnabled() && app.otpService().hasSecret(username)) {
                    web.changePasswordForm(aResponse, state, back, contextId, username, "Verification code is empty");
                    return;
                }
                try {
                    app.authService().changePassword(username, password, newPassword);
                } catch (AuthenticationException e) {
                    web.changePasswordForm(aResponse, state, back, contextId, username, "Could not change password");
                    return;
                }
                LOG.warn("User {} changed password", username);
                // a token stolen before the change must not outlive it, even if the next step fails; the login
                // name selects the bind DN, so it identifies the entry even when the uid is not readable yet
                loginGeneration = webauthn.service().revokeAfterPasswordChange(knownUid, username);
                try {
                    principal = app.authService().authenticatePrincipal(username, newPassword);
                } catch (AuthenticationException | UserMustChangePasswordException e) {
                    web.loginForm(aResponse, state, back, contextId, username, "Password changed. Please log in with the new password.");
                    return;
                }
                if (!principal.getCanonicalUid().equals(knownUid)) {
                    // uid becomes readable only now (expired password): end its sessions too; the bump is ours,
                    // so take the new generation for this request
                    loginGeneration = webauthn.service().revokeAfterPasswordChange(principal.getCanonicalUid(), username);
                }
            } else {
                principal = app.authService().authenticatePrincipal(username, password);
            }
        } catch (UserMustChangePasswordException e) {
            LOG.warn("User {} must change password", username);
            web.changePasswordForm(aResponse, state, back, contextId, username, "User must change password");
            return;
        } catch (AuthenticationException e) {
            attempt.failed();
            LOG.warn("User {} login failed", username);
            form(aResponse, aChangePassword, state, back, contextId, username, "Authentication failed");
            return;
        }

        String uid = principal.getCanonicalUid();
        EffectivePolicy policy;
        try {
            policy = webauthn.resolver().resolve(principal.getGroups(), policyId);
        } catch (IllegalArgumentException e) {
            policy = null;
        }
        boolean validUid = FileCredentialRepository.isValidUid(uid);
        boolean known = !validUid || !webauthn.repository().isFailed();
        boolean usable = validUid && known;
        UserRecord record = usable ? webauthn.repository().find(uid).orElse(null) : null;
        boolean eligible = policy != null && AccessChecker.hasEligible(record, policy);
        boolean grant = record != null && record.enrollmentGrant() != null && record.enrollmentGrant().isUsable(System.currentTimeMillis());
        MethodSelector.Method method = policy == null ? MethodSelector.Method.DENY
                : MethodSelector.select(policy, app.otpEnabled(), codeProvided || totpVerified, eligible, usable, known, grant);

        switch (method) {
            case DENY -> {
                attempt.succeeded();
                if (!known) {
                    LOG.error("Credential storage is unavailable; login of {} refused", uid);
                    form(aResponse, false, state, back, contextId, username, "Internal error. Please try again later.");
                    return;
                }
                Audit.log("access_denied_by_policy", "uid", uid, "policyId", policyId, "stage", "login");
                form(aResponse, false, state, back, contextId, username, "Access denied by policy");
            }
            case TOTP -> {
                if (!totpVerified && !app.otpService().checkCode(username, parseCode(otp))) {
                    attempt.failed();
                    LOG.warn("User {} OTP verification failed", username);
                    form(aResponse, aChangePassword, state, back, contextId, username, "Authentication failed");
                    return;
                }
                attempt.succeeded();
                issue(aRequest, aResponse, state, generation, loginGeneration, principal, AuthenticationMethod.LDAP_TOTP, back, policyId);
            }
            case LDAP_ONLY -> {
                attempt.succeeded();
                issue(aRequest, aResponse, state, generation, loginGeneration, principal, AuthenticationMethod.LDAP_ONLY, back, policyId);
            }
            case CODE_REQUIRED -> {
                attempt.succeeded();
                form(aResponse, false, state, back, contextId, username,
                        aChangePassword ? "Password changed. Please log in with your verification code." : "Verification code is empty");
            }
            case WEBAUTHN, RECOVERY -> {
                attempt.succeeded();
                if (!webauthn.service().beginPreAuth(state, generation, PreAuth.create(principal, policyId, back, loginGeneration))) {
                    web.loginForm(aResponse, state, back, contextId, null, "Your login was interrupted. Please log in again.");
                    return;
                }
                LOG.info("User {} passed LDAP, second factor {}", uid, method);
                aResponse.setStatus(HttpServletResponse.SC_SEE_OTHER);
                aResponse.setHeader("Location", WebAuthnWeb.AUTH_URL + "/verify");
            }
        }
    }

    private void issue(HttpServletRequest aRequest, HttpServletResponse aResponse, BrowserState aState, long aGeneration,
                       long aLoginGeneration, LdapPrincipal aPrincipal, AuthenticationMethod aMethod, String aBack, String aPolicyId) throws IOException {
        Optional<String> issued = webauthn.service().issueSession(aState, aGeneration, Session.withoutWebAuthn(aPrincipal.getCanonicalUid(),
                aPrincipal.getDisplayName(), aPrincipal.getGroups(), aMethod, aPrincipal.getLdapAuthTime()).withLoginName(aPrincipal.getLoginName()), aLoginGeneration);
        if (issued.isEmpty()) {
            web.loginForm(aResponse, aState, aBack, null, null, "Your login was interrupted. Please log in again.");
            return;
        }
        String token = issued.get();
        Audit.log("authentication_succeeded", "uid", aPrincipal.getCanonicalUid(), "method", aMethod.name(), "policyId", aPolicyId);
        WebAuthnWeb.issueSessionCookie(aRequest, aResponse, token);
        aResponse.sendRedirect(aBack);
    }

    private void form(HttpServletResponse aResponse, boolean aChangePassword, BrowserState aState, String aBack, String aContextId,
                      String aUsername, String aReason) throws IOException {
        if (aChangePassword) {
            web.changePasswordForm(aResponse, aState, aBack, aContextId, aUsername, aReason);
        } else {
            web.loginForm(aResponse, aState, aBack, aContextId, aUsername, aReason);
        }
    }

    private static String newPasswordProblem(String aPassword, String aRepeated) {
        if (tooLong(aPassword, MAX_PASSWORD) || tooLong(aRepeated, MAX_PASSWORD)) {
            return "New password is too long";
        }
        if (StringUtils.isEmpty(aPassword) || StringUtils.isEmpty(aRepeated)) {
            return "New password is empty";
        }
        if (!aPassword.equals(aRepeated)) {
            return "New passwords do not match";
        }
        return null;
    }

    private static long parseCode(String aCode) {
        try {
            return Long.parseLong(aCode.trim());
        } catch (RuntimeException e) {
            return -1;
        }
    }

    static String backFromParameter(HttpServletRequest aRequest) {
        String raw = aRequest.getParameter(WebAuthnWeb.BACK_URL_NAME);
        if (raw == null || tooLong(raw, MAX_BACK)) {
            return null;
        }
        return BackUrl.normalize(raw).orElse(null);
    }
}
