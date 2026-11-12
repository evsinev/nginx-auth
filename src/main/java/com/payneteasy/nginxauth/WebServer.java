package com.payneteasy.nginxauth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.payneteasy.nginxauth.admin.AdminCli;
import com.payneteasy.nginxauth.admin.AdminServlet;
import com.payneteasy.nginxauth.service.IAuthService;
import com.payneteasy.nginxauth.service.impl.AuthServiceImpl;
import com.payneteasy.nginxauth.service.impl.OneTimePasswordServiceImpl;
import com.payneteasy.nginxauth.service.impl.RateLimiter;
import com.payneteasy.nginxauth.servlet.*;
import com.payneteasy.nginxauth.servlet.api.ApiCheckUsernameOtpServlet;
import com.payneteasy.nginxauth.servlet.api.ApiCheckUsernamePasswordServlet;
import com.payneteasy.nginxauth.util.SettingsManager;
import com.payneteasy.nginxauth.webauthn.WebAuthnContext;
import jakarta.servlet.Servlet;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static com.payneteasy.nginxauth.util.SettingsManager.getAuthUrl;
import static com.payneteasy.nginxauth.util.StringUtils.isEmpty;

/**
 *
 */
public class WebServer {
    private static final Logger LOG = LoggerFactory.getLogger(WebServer.class);

    static final String MAIN_CONNECTOR  = "main";
    static final String ADMIN_CONNECTOR = "admin";

    public static void main(String[] args) throws Exception {

        if (args.length > 0 && "admin".equals(args[0])) {
            AdminCli.main(Arrays.copyOfRange(args, 1, args.length));
            return;
        }

        setTrustedStorePassword();

        SettingsManager.logCurrentSettings();
        RateLimiter.getInstance();

        Server server;
        try {
            AppContext app = AppContext.fromSettings();
            server = createServer(app, SettingsManager.getConnectorPort());
        } catch (Exception e) {
            LOG.error("Can't start: {}", e.getMessage());
            System.exit(1);
            return;
        }

        try {
            server.start();
            server.join();
        } catch (Exception e) {
            LOG.error("Can't start server", e);
            System.exit(1);
        }
    }

    public static Server createServer(AppContext aApp, int aPort) {
        Server server = new Server();

        ServerConnector main = new ServerConnector(server);
        main.setName(MAIN_CONNECTOR);
        main.setPort(aPort);
        server.addConnector(main);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
        context.setContextPath("/");
        context.setVirtualHosts(List.of("@" + MAIN_CONNECTOR));

        add(context, new CheckAccessServlet(aApp)        , "/*"                              );
        add(context, new ShowLoginFormServlet(aApp)      , getAuthUrl() + "/*"               );
        add(context, new LoginFormServlet(aApp)          , getAuthUrl() + "/login"           );
        add(context, new ChangePasswordServlet(aApp)     , getAuthUrl() + "/change-password" );
        add(context, new LogoutServlet(aApp)             , getAuthUrl() + "/logout"          );

        add(context, new NginxAuthRequestCheckServlet(aApp), getAuthUrl() + "/nginx-auth-request-check" );

        WebAuthnContext webauthn = aApp.webauthn();
        if (webauthn != null) {
            add(context, new WebAuthnApiServlet(aApp)    , getAuthUrl() + "/webauthn/*"      );
            add(context, new VerifyPageServlet(aApp)     , getAuthUrl() + "/verify"          );
            add(context, new RecoveryServlet(aApp)       , getAuthUrl() + "/recovery"        );
            add(context, new CredentialsServlet(aApp)    , getAuthUrl() + "/credentials"     );
            add(context, new StaticResourceServlet()     , getAuthUrl() + "/static/*"        );
        }

        if (SettingsManager.isApiCheckEnabled()) {
            addApiCheckServlets(context, aApp.authService());
        }

        ContextHandlerCollection contexts = new ContextHandlerCollection();
        contexts.addHandler(context);

        if (webauthn != null && webauthn.config().isAdminEnabled()) {
            ServerConnector admin = new ServerConnector(server);
            admin.setName(ADMIN_CONNECTOR);
            admin.setHost("127.0.0.1");
            admin.setPort(webauthn.config().getAdminPort());
            server.addConnector(admin);

            ServletContextHandler adminContext = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
            adminContext.setContextPath("/");
            adminContext.setVirtualHosts(List.of("@" + ADMIN_CONNECTOR));
            add(adminContext, new AdminServlet(webauthn), "/admin/webauthn/*");
            contexts.addHandler(adminContext);
            LOG.info("WebAuthn admin API on 127.0.0.1:{}", webauthn.config().getAdminPort());
        }

        server.setHandler((Handler) contexts);
        return server;
    }

    private static void add(ServletContextHandler aContext, Servlet aServlet, String aPath) {
        ServletHolder holder = new ServletHolder(aServlet);
        holder.setAsyncSupported(true);
        aContext.addServlet(holder, aPath);
    }

    private static void addApiCheckServlets(ServletContextHandler context, IAuthService authService) {
        LOG.info("Adding api check servlets: /nginx-auth/api/check/check-password and /nginx-auth/api/check/check-otp");

        OneTimePasswordServiceImpl oneTimePasswordService = OneTimePasswordServiceImpl.getInstance();
        Set<String>                accessTokens           = SettingsManager.getAccessTokens();
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
        if(isEmpty(password)) {
            return;
        }

        System.setProperty("javax.net.ssl.trustStorePassword", password);
        LOG.info("Setting javax.net.ssl.trustStorePassword from the TRUST_STORE_PASSWORD. Password length is {}", password.length());
    }
}
