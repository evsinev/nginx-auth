package com.payneteasy.nginxauth;

import com.google.common.base.Strings;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.payneteasy.nginxauth.service.IAuthService;
import com.payneteasy.nginxauth.service.impl.AuthServiceImpl;
import com.payneteasy.nginxauth.service.impl.OneTimePasswordServiceImpl;
import com.payneteasy.nginxauth.servlet.*;
import com.payneteasy.nginxauth.servlet.api.ApiCheckUsernameOtpServlet;
import com.payneteasy.nginxauth.servlet.api.ApiCheckUsernamePasswordServlet;
import com.payneteasy.nginxauth.util.SettingsManager;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

import static com.payneteasy.nginxauth.util.SettingsManager.getAuthUrl;

/**
 *
 */
public class WebServer {
    private static final Logger LOG = LoggerFactory.getLogger(WebServer.class);

    public static void main(String[] args) throws Exception {

        setTrustedStorePassword();

        SettingsManager.logCurrentSettings();

        Server server = new Server(SettingsManager.getConnectorPort());

        ServletContextHandler context  = new ServletContextHandler(server, "/", ServletContextHandler.NO_SESSIONS);

        context.addServlet(CheckAccessServlet.class     ,  "/*"                              ).setAsyncSupported(true);
        context.addServlet(ShowLoginFormServlet.class   ,  getAuthUrl() + "/*"               ).setAsyncSupported(true);
        context.addServlet(LoginFormServlet.class       ,  getAuthUrl() + "/login"           ).setAsyncSupported(true);
        context.addServlet(ChangePasswordServlet.class  ,  getAuthUrl() + "/change-password" ).setAsyncSupported(true);
        context.addServlet(LogoutServlet.class          ,  getAuthUrl() + "/logout"          ).setAsyncSupported(true);

        context.addServlet(NginxAuthRequestCheckServlet.class,  getAuthUrl() + "/nginx-auth-request-check" ).setAsyncSupported(true);

        if (SettingsManager.isApiCheckEnabled()) {
            addApiCheckServlets(context);
        }

        server.setHandler(context);

        try {
            server.start();
            server.join();
        } catch (Exception e) {
            LOG.error("Can't start server", e);
            System.exit(1);
        }
    }

    private static void addApiCheckServlets(ServletContextHandler context) {
        LOG.info("Adding api check servlets: /nginx-auth/api/check/check-password and /nginx-auth/api/check/check-otp");

        OneTimePasswordServiceImpl oneTimePasswordService = new OneTimePasswordServiceImpl();
        Set<String>                accessTokens           = SettingsManager.getAccessTokens();
        IAuthService               authService            = new AuthServiceImpl();
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

        context.addServlet(new ServletHolder(new ApiCheckUsernamePasswordServlet(
                  authService
                , gson
                , accessTokens
        )), "/nginx-auth/api/check/check-password/*");

        context.addServlet(new ServletHolder(new ApiCheckUsernameOtpServlet(
                oneTimePasswordService
                , gson
                , accessTokens
        )), "/nginx-auth/api/check/check-otp/*");
    }

    private static void setTrustedStorePassword() {
        String password = System.getenv("TRUST_STORE_PASSWORD");
        if(Strings.isNullOrEmpty(password)) {
            return;
        }

        System.setProperty("javax.net.ssl.trustStorePassword", password);
        LOG.info("Setting javax.net.ssl.trustStorePassword from the TRUST_STORE_PASSWORD. Password length is {}", password.length());
    }
}
