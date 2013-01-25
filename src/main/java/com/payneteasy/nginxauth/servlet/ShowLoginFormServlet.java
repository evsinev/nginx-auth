package com.payneteasy.nginxauth.servlet;

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
        velocity.add("BACK_URL_VALUE", backUrl);

        velocity.processTemplate(ShowLoginFormServlet.class, "/pages/login-form.vm", aResponse.getWriter());

    }
}
