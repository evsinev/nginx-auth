package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.service.INonceManager;
import com.payneteasy.nginxauth.service.impl.NonceManagerImpl;
import com.payneteasy.nginxauth.util.CookiesManager;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.SettingsManager;
import com.payneteasy.nginxauth.util.VelocityBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;

import static com.payneteasy.nginxauth.util.SettingsManager.getTokenCookieAssignedName;
import static com.payneteasy.nginxauth.util.SettingsManager.getTokenCookieName;

/**
 *
 */
public class ShowLoginFormServlet extends HttpServlet {
    private static final Logger LOG = LoggerFactory.getLogger(ShowLoginFormServlet.class);

    private static final String BACK_URL_NAME = SettingsManager.getBackUrlName();

    @Override
    protected void service(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        HttpRequestUtil.logDebug(aRequest);

        String backUrl = aRequest.getParameter(BACK_URL_NAME);

        VelocityBuilder velocity = new VelocityBuilder();
        velocity.add("FORM_ACTION", "/auth/login");
        velocity.add("BACK_URL_NAME",  BACK_URL_NAME);
        try {
            new URL(backUrl);
            velocity.add("BACK_URL_VALUE", backUrl);
        } catch (Exception e) {
            velocity.add("REASON", "Invalid back url");
        }
        velocity.add("NONCE", theNonceManager.addNonce());

        // check http only
        CookiesManager cookiesManager = new CookiesManager(aRequest, aResponse);
        if(!cookiesManager.hasCookie(getTokenCookieName()) && cookiesManager.hasCookie(getTokenCookieAssignedName())) {
            velocity.add("REASON", "Please check secure cookie. Do not use http when secure cookies is enabled.");
        }

        velocity.processTemplate(ShowLoginFormServlet.class, "/pages/login-form.vm", aResponse.getWriter());

    }

    private INonceManager theNonceManager = NonceManagerImpl.getInstance();


}
