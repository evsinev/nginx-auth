package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.service.*;
import com.payneteasy.nginxauth.service.impl.AuthServiceImpl;
import com.payneteasy.nginxauth.service.impl.NonceManagerImpl;
import com.payneteasy.nginxauth.service.impl.RateLimiter;
import com.payneteasy.nginxauth.service.impl.TokenManagerImpl;
import com.payneteasy.nginxauth.util.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

public class LoginFormServlet extends HttpServlet {
    private static final Logger LOG = LoggerFactory.getLogger(LoginFormServlet.class);

    private static final String  BACK_URL_NAME = SettingsManager.getBackUrlName();
    private static final boolean OTP_ENABLED   = SettingsManager.isOtpEnabled();

    static final int MAX_USERNAME = 256;
    static final int MAX_PASSWORD = 1024;
    static final int MAX_OTP      = 10;
    static final int MAX_BACK     = 2048;
    static final int MAX_NONCE    = 64;

    @Override
    protected void doPost(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        HttpRequestUtil.logDebug(aRequest);

        String backRaw  = aRequest.getParameter(BACK_URL_NAME);
        String username = aRequest.getParameter("j_username");
        String password = aRequest.getParameter("j_password");
        String otp      = aRequest.getParameter("j_code");
        String nonce    = aRequest.getParameter("j_nonce");

        if (StringUtils.isEmpty(backRaw)) {
            showErrorForm(aResponse, "", "", "Back url is empty");
            return;
        }
        if (tooLong(backRaw, MAX_BACK)) {
            showErrorForm(aResponse, "", "", "Bad back url");
            return;
        }
        Optional<String> backOpt = BackUrl.normalize(backRaw);
        if (!backOpt.isPresent()) {
            showErrorForm(aResponse, "", "", "Bad back url");
            return;
        }
        String backUrl = backOpt.get();

        if (tooLong(nonce, MAX_NONCE)) {
            showErrorForm(aResponse, backUrl, "", "Invalid nonce");
            return;
        }
        if (StringUtils.isEmpty(nonce)) {
            showErrorForm(aResponse, backUrl, "", "Nonce is empty");
            return;
        }
        if (!theNonceManager.checkNonce(nonce)) {
            showErrorForm(aResponse, backUrl, "", "Invalid nonce");
            return;
        }

        if (tooLong(username, MAX_USERNAME)) {
            showErrorForm(aResponse, backUrl, "", "Username is too long");
            return;
        }
        if (StringUtils.isEmpty(username)) {
            showErrorForm(aResponse, backUrl, "", "Username is empty");
            return;
        }

        if (tooLong(password, MAX_PASSWORD)) {
            showErrorForm(aResponse, backUrl, username, "Password is too long");
            return;
        }
        if (StringUtils.isEmpty(password)) {
            showErrorForm(aResponse, backUrl, username, "Password is empty");
            return;
        }

        RateLimiter.Attempt attempt = LoginAttempts.begin(aRequest, username);
        attempt.awaitDelay();
        if (attempt.denied()) {
            LOG.warn("Login throttled [user:{}]", username);
            showErrorForm(aResponse, backUrl, username, "Authentication failed");
            return;
        }

        try {
            if (OTP_ENABLED) {
                if (tooLong(otp, MAX_OTP)) {
                    showErrorForm(aResponse, backUrl, username, "Verification code is invalid");
                    return;
                }
                if (StringUtils.isEmpty(otp)) {
                    showErrorForm(aResponse, backUrl, username, "Verification code is empty");
                    return;
                }

                long verificationCode = -1;
                try {
                    verificationCode = Long.parseLong(otp);
                } catch (Exception e) {
                    LOG.debug("Verification code is not number [user:{}]", username);
                }

                theAuthService.authenticate(username, password, verificationCode, canCheckAccess());
            } else {
                theAuthService.authenticate(username, password, canCheckAccess());
            }

            LOG.warn("User {} login success", username);

            doCustomAction(username, password, aRequest);

            attempt.succeeded();

            CookiesManager cookies = new CookiesManager(aRequest, aResponse);
            cookies.add(SettingsManager.getTokenCookieName(), theTokenManager.createToken(username));
            cookies.addAssignedMarker(SettingsManager.getTokenCookieAssignedName(), System.currentTimeMillis() + "");
            aResponse.sendRedirect(backUrl);

        } catch (ChangePasswordException e) {
            LOG.warn("Failed to change password for user "+username + " "+e.getMessage());
            showChangePasswordForm(aResponse, backUrl, username, e.getMessage());

        } catch (UserMustChangePasswordException e) {
            LOG.warn("User {} must change password", username);
            showChangePasswordForm(aResponse, backUrl, username, "User must change password");

        } catch (Exception e) {
            LOG.error("User "+username+" login failed", e);
            attempt.failed();
            showErrorForm(aResponse, backUrl, username, "Authentication failed");
        }
    }

    static boolean tooLong(String value, int max) {
        return value != null && value.length() > max;
    }

    static void putNonce(VelocityBuilder velocity, INonceManager nonceManager) {
        String nonce = nonceManager.addNonce();
        if (nonce == null) {
            velocity.add("NONCE", "");
            velocity.add("REASON", "Service busy");
        } else {
            velocity.add("NONCE", nonce);
        }
    }

    public boolean canCheckAccess() {
        return true;
    }

    public void doCustomAction(String aUsername, String aCurrentPassword, HttpServletRequest aRequest) throws ChangePasswordException {

    }

    private void showChangePasswordForm(HttpServletResponse aResponse, String backUrl, String aUsername, String aErrorMessage) throws IOException {
        showForm("/auth/change-password", aResponse, backUrl, aUsername, aErrorMessage, "/pages/change-password-form.vm");
    }

    private void showErrorForm(HttpServletResponse aResponse, String backUrl, String aUsername, String aErrorMessage) throws IOException {
        showForm("/auth/login", aResponse, backUrl, aUsername, aErrorMessage, "/pages/login-form.vm");
    }

    private void showForm(String aAction, HttpServletResponse aResponse, String backUrl, String aUsername, String aErrorMessage, String aFormTemplate) throws IOException {
        HttpRequestUtil.setNoStoreHeaders(aResponse);

        VelocityBuilder velocity = new VelocityBuilder();

        velocity.add("BACK_URL_NAME"  ,  BACK_URL_NAME              );
        velocity.add("BACK_URL_VALUE" , backUrl                     );
        velocity.add("FORM_ACTION"    , aAction                     );
        velocity.add("REASON"         , aErrorMessage               );
        velocity.add("USERNAME"       , aUsername                   );
        velocity.add("OTP_ENABLED"    , OTP_ENABLED                 );
        putNonce(velocity, theNonceManager);

        velocity.processTemplate(LoginFormServlet.class, aFormTemplate, aResponse.getWriter());
    }

    final IAuthService theAuthService = new AuthServiceImpl();
    private ITokenManager theTokenManager = TokenManagerImpl.getInstance();
    private INonceManager theNonceManager = NonceManagerImpl.getInstance();

}
