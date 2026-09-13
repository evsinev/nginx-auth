package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.service.ITokenManager;
import com.payneteasy.nginxauth.service.impl.TokenManagerImpl;
import com.payneteasy.nginxauth.util.CookiesManager;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.SettingsManager;
import com.payneteasy.nginxauth.util.VelocityBuilder;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class LogoutServlet extends HttpServlet {

    private final ITokenManager tokenManager = TokenManagerImpl.getInstance();

    @Override
    protected void doGet(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        logout(aRequest, aResponse);
    }

    @Override
    protected void doPost(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        logout(aRequest, aResponse);
    }

    private void logout(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        HttpRequestUtil.logDebug(aRequest);
        HttpRequestUtil.setNoStoreHeaders(aResponse);

        CookiesManager cookies = new CookiesManager(aRequest, aResponse);
        String token = cookies.getCookieValue(SettingsManager.getTokenCookieName());
        tokenManager.invalidateToken(token);
        cookies.clear();

        VelocityBuilder velocity = new VelocityBuilder();
        velocity.processTemplate(LogoutServlet.class, "/pages/logout-form.vm.html", aResponse.getWriter());
    }
}
