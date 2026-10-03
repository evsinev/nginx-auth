package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.AppContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.payneteasy.nginxauth.util.HttpRequestUtil.logDebug;

public class NginxAuthRequestCheckServlet extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger( NginxAuthRequestCheckServlet.class );

    private final AccessGate accessGate;

    public NginxAuthRequestCheckServlet(AppContext aApp) {
        accessGate = new AccessGate(aApp);
    }

    @Override
    protected void service(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        logDebug(aRequest);

        AccessGate.Result result = accessGate.evaluate(aRequest, aResponse, aRequest.getHeader("X-Original-URI"));
        switch (result.outcome()) {
            case ALLOW -> aResponse.setStatus(HttpServletResponse.SC_OK);
            case FORBIDDEN -> aResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            case LOGIN -> {
                LOG.warn("Bad token for url {}", aRequest.getRequestURL());
                aResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }
    }
}
