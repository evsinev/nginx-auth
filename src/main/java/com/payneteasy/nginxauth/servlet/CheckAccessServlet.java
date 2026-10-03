package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.AppContext;
import com.payneteasy.nginxauth.util.HttpRequestUtil;
import com.payneteasy.nginxauth.util.SettingsManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class CheckAccessServlet extends HttpServlet {
    private static final Logger LOG = LoggerFactory.getLogger(CheckAccessServlet.class);

    private static final String BACK_URL_NAME     = SettingsManager.getBackUrlName();
    private static final String AUTH_URL          = SettingsManager.getAuthUrl();
    private static final String INTERNAL_PREFIX   = SettingsManager.getInternalPrefix();
    private static final String X_ACCEL_REDIRECT  = SettingsManager.getXAccessRedirect();

    private final AccessGate accessGate;

    public CheckAccessServlet(AppContext aApp) {
        accessGate = new AccessGate(aApp);
    }

    @Override
    protected void service(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {

        HttpRequestUtil.logDebug(aRequest);

        String back = backUrl(aRequest);
        AccessGate.Result result = accessGate.evaluate(aRequest, aResponse, back);
        switch (result.outcome()) {
            case ALLOW -> aResponse.setHeader(X_ACCEL_REDIRECT, createInternalUriRedirect(aRequest));
            case FORBIDDEN -> aResponse.sendError(HttpServletResponse.SC_FORBIDDEN);
            case LOGIN -> aResponse.sendRedirect(createRedirectUrlToAuth(back, result.contextId()));
        }
    }

    private static String backUrl(HttpServletRequest aRequest) {
        StringBuilder back = new StringBuilder();
        back.append(aRequest.getRequestURI());
        String queryString = aRequest.getQueryString();
        if (queryString != null) {
            back.append('?').append(queryString);
        }
        return back.toString();
    }

    private String createRedirectUrlToAuth(String aBack, String aContextId) {
        try {
            String url = AUTH_URL + "?" + BACK_URL_NAME + "=" + URLEncoder.encode(aBack, "utf-8");
            if (aContextId != null) {
                url += "&ctx=" + URLEncoder.encode(aContextId, "utf-8");
            }
            return url;
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
