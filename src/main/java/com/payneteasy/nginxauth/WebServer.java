package com.payneteasy.nginxauth;

import com.google.common.base.Strings;
import com.payneteasy.nginxauth.servlet.*;
import com.payneteasy.nginxauth.util.SettingsManager;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

        server.setHandler(context);

        try {
            server.start();
            server.join();
        } catch (Exception e) {
            LOG.error("Can't start server", e);
            System.exit(1);
        }
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
