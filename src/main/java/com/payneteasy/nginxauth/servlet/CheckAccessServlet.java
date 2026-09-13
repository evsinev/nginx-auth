package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.util.CheckCookiesAccess;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.SettingsManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class CheckAccessServlet extends HttpServlet {
    private static final Logger LOG = LoggerFactory.getLogger(CheckAccessServlet.class);

    private static final String BACK_URL_NAME     = SettingsManager.getBackUrlName();
    private static final String AUTH_URL          = SettingsManager.getAuthUrl();
    private static final String INTERNAL_PREFIX   = SettingsManager.getInternalPrefix();
    private static final String X_ACCEL_REDIRECT  = SettingsManager.getXAccessRedirect();

    private final CheckCookiesAccess checkCookiesAccess = new CheckCookiesAccess();

    @Override
    protected void service(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {

        HttpRequestUtil.logDebug(aRequest);

        if (checkCookiesAccess.isValidToken(aRequest, aResponse)) {
            aResponse.setHeader(X_ACCEL_REDIRECT, createInternalUriRedirect(aRequest));
        } else {
            aResponse.sendRedirect(createRedirectUrlToAuth(aRequest));
        }
    }

    private String createRedirectUrlToAuth(HttpServletRequest aRequest) {
        StringBuilder back = new StringBuilder();
        back.append(aRequest.getRequestURI());
        String queryString = aRequest.getQueryString();
        if (queryString != null) {
            back.append('?').append(queryString);
        }
        try {
            return AUTH_URL + "?" + BACK_URL_NAME + "=" + URLEncoder.encode(back.toString(), "utf-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Can't create url", e);
        }
    }

    private static String createInternalUriRedirect(HttpServletRequest aRequest) {
        StringBuilder sb = new StringBuilder();
        sb.append(INTERNAL_PREFIX);
        sb.append(aRequest.getRequestURI().substring(1)); // skip first symbol
        String queryString = aRequest.getQueryString();
        if(queryString!=null) {
            sb.append("?");
            sb.append(queryString);
        }
        LOG.info("Internal redirect {}", sb);
        return sb.toString();
    }

}
