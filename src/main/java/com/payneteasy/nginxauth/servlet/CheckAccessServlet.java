package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.service.IAuthService;
import com.payneteasy.nginxauth.service.ITokenManager;
import com.payneteasy.nginxauth.service.impl.TokenManagerImpl;
import com.payneteasy.nginxauth.util.CookiesManager;
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
import java.util.Enumeration;

/**
 *
 */
public class CheckAccessServlet extends HttpServlet {
    private static final Logger LOG = LoggerFactory.getLogger(CheckAccessServlet.class);

    private static final String TOKEN_COOKIE_NAME = SettingsManager.getTokenCookieName();
    private static final String BACK_URL_NAME     = SettingsManager.getBackUrlName();
    private static final String AUTH_URL          = SettingsManager.getAuthUrl();
    private static final String INTERNAL_PREFIX   = SettingsManager.getInternalPrefix();
    private static final String X_ACCEL_REDIRECT  = SettingsManager.getXAccessRedirect();

    @Override
    protected void service(HttpServletRequest aRequest, HttpServletResponse aResponse) throws ServletException, IOException {

        // Log request
        HttpRequestUtil.logDebug(aRequest);

        // check access token cookie
        if(isValidToken(aRequest, aResponse)) {
            // nginx internal redirect
            aResponse.setHeader(X_ACCEL_REDIRECT, createInternalUriRedirect(aRequest));
        } else {
            // redirect to /auth
            aResponse.sendRedirect(createRedirectUrlToAuth(aRequest));
        }
    }

    private String createRedirectUrlToAuth(HttpServletRequest aRequest) {
        StringBuilder sb = new StringBuilder();
        sb.append(AUTH_URL);
        sb.append("?");
        sb.append(BACK_URL_NAME);
        sb.append("=");
        String requestUrl = removeDangerousCharacters(getRequestUrl(aRequest));
        try {
            sb.append(URLEncoder.encode(requestUrl, "utf-8"));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Can't create url", e);
        }
        return sb.toString();
    }

    private static String removeDangerousCharacters(String aRequestUrl) {
        if(aRequestUrl == null) {
            return null;
        }

        if(aRequestUrl.contains("<script")) {
            return aRequestUrl.replace("<script", "noscript");
        }
        return aRequestUrl;
    }

    private boolean isValidToken(HttpServletRequest aRequest, HttpServletResponse aResponse) {
        CookiesManager cookies = new CookiesManager(aRequest, aResponse);
        String token = cookies.getCookieValue(TOKEN_COOKIE_NAME);
        if(token==null) {
            token = aRequest.getParameter(TOKEN_COOKIE_NAME);
        }

        return theTokenManager.validateToken(token);
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



    public static String getRequestUrl(HttpServletRequest aRequest) {
        StringBuffer reqUrl = aRequest.getRequestURL();
        String queryString = aRequest.getQueryString();
        if (queryString != null) {
            reqUrl.append("?");
            reqUrl.append(queryString);

        }
        return reqUrl.toString();
    }

    private ITokenManager theTokenManager = TokenManagerImpl.getInstance();
}
