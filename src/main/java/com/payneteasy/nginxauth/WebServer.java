package com.payneteasy.nginxauth;

import com.payneteasy.nginxauth.servlet.CheckAccessServlet;
import com.payneteasy.nginxauth.servlet.LoginFormServlet;
import com.payneteasy.nginxauth.servlet.ShowLoginFormServlet;
import com.payneteasy.nginxauth.util.SettingsManager;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
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
        SettingsManager.logCurrentSettings();

        Server server = new Server();
        Connector connector=new SelectChannelConnector();
        connector.setPort(SettingsManager.getConnectorPort());
        server.setConnectors(new Connector[]{connector});

        ServletContextHandler context  = new ServletContextHandler(server, "/", ServletContextHandler.NO_SESSIONS);
        context.addServlet(CheckAccessServlet.class,  "/*").setAsyncSupported(true);
        context.addServlet(LoginFormServlet.class,  getAuthUrl()+"/login").setAsyncSupported(true);
        context.addServlet(ShowLoginFormServlet.class,  getAuthUrl()+"/*").setAsyncSupported(true);

        server.setHandler(context);

        try {
            server.start();
            server.join();
        } catch (Exception e) {
            LOG.error("Can't start server", e);
            System.exit(1);
        }
    }
}
