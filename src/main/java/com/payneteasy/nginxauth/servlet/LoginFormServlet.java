package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.service.IAuthService;
import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import com.payneteasy.nginxauth.service.ITokenManager;
import com.payneteasy.nginxauth.service.impl.AuthServiceImpl;
import com.payneteasy.nginxauth.service.impl.TokenManagerImpl;
import com.payneteasy.nginxauth.util.CookiesManager;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.SettingsManager;
import com.payneteasy.nginxauth.util.VelocityBuilder;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

/**
 *
 */
public class LoginFormServlet extends HttpServlet {
    private static final Logger LOG = LoggerFactory.getLogger(LoginFormServlet.class);

    private static final String BACK_URL_NAME = SettingsManager.getBackUrlName();

    @Override
    protected void service(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        HttpRequestUtil.logDebug(aRequest);

        String backUrl  =  aRequest.getParameter(BACK_URL_NAME);
        String username = aRequest.getParameter("j_username");
        String password = aRequest.getParameter("j_password");
        String otp      = aRequest.getParameter("j_code");

        if(StringUtils.isEmpty(backUrl)) {
            showErrorForm(aResponse, "", "", "Back url is empty");
            return ;
        }

        if(StringUtils.isEmpty(username)) {
            showErrorForm(aResponse, backUrl, "", "Username is empty");
            return;
        }

        if(StringUtils.isEmpty(password)) {
            showErrorForm(aResponse, backUrl, username, "Password is empty");
            return;
        }

        if(StringUtils.isEmpty(otp)) {
            showErrorForm(aResponse, backUrl, username, "Verification code is empty");
            return;
        }

        long verificationCode = 0 ;
        try {
            verificationCode = Long.parseLong(otp);
        } catch (Exception e) {
            LOG.warn("Verification code is not number [user:{}, code:{}]", username, otp);
        }

        try {
            theAuthService.authenticate(username, password, verificationCode);
            LOG.warn("User {} login success", username);
            CookiesManager cookies = new CookiesManager(aRequest, aResponse);
            cookies.add(SettingsManager.getTokenCookieName(), theTokenManager.createToken());
            aResponse.sendRedirect(backUrl);

        } catch (Exception e) {
            LOG.warn("User {} login failed: {}", username, e.getMessage());
            showErrorForm(aResponse, backUrl, username, e.getMessage());
        }


    }

    private void showErrorForm(HttpServletResponse aResponse, String backUrl, String aUsername, String aErrorMessage) throws IOException {
        VelocityBuilder velocity = new VelocityBuilder();
        velocity.add("BACK_URL_NAME",  BACK_URL_NAME);
        velocity.add("BACK_URL_VALUE", backUrl);
        velocity.add("FORM_ACTION", "/auth/login");
        velocity.add("REASON", aErrorMessage);
        velocity.add("USERNAME", aUsername);
        velocity.processTemplate(LoginFormServlet.class, "/pages/login-form.vm", aResponse.getWriter());
    }

//    private String createBackRedirectUrl(String aBackUrl) {
//        StringBuilder sb = new StringBuilder();
//        sb.append(aBackUrl);
//        if(aBackUrl.contains("?")) {
//            sb.append("&");
//        } else {
//            sb.append("?");
//        }
//        sb.append(SettingsManager.getTokenCookieName());
//        sb.append("=");
//        sb.append(UUID.randomUUID());
//        LOG.info("redirect {}", sb);
//        return sb.toString();
//    }

    private final IAuthService theAuthService = new AuthServiceImpl();
    private ITokenManager theTokenManager = TokenManagerImpl.getInstance();

}
