package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.util.CookiesManager;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.VelocityBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LogoutServlet extends HttpServlet {

    @Override
    protected void service(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        HttpRequestUtil.logDebug(aRequest);

        CookiesManager cookies = new CookiesManager(aRequest, aResponse);
        cookies.clear();

        VelocityBuilder velocity = new VelocityBuilder();
        velocity.processTemplate(LogoutServlet.class, "/pages/logout-form.vm.html", aResponse.getWriter());

    }
}
