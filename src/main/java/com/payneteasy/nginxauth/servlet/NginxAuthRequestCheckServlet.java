package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.util.CheckCookiesAccess;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.payneteasy.nginxauth.util.HttpRequestUtil.logDebug;

public class NginxAuthRequestCheckServlet extends HttpServlet {

    private static final Logger LOG = LoggerFactory.getLogger( NginxAuthRequestCheckServlet.class );

    private final CheckCookiesAccess checkCookiesAccess = new CheckCookiesAccess();

    @Override
    protected void service(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {
        logDebug(aRequest);

        if (checkCookiesAccess.isValidToken(aRequest, aResponse)) {
            aResponse.setStatus(HttpServletResponse.SC_OK);
        } else {
            LOG.warn("Bad token for url {}", aRequest.getRequestURL());
            aResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }
}
