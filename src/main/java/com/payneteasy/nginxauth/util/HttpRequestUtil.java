package com.payneteasy.nginxauth.util;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Enumeration;
import java.util.Locale;

import static com.payneteasy.nginxauth.util.StringUtils.hasText;

public class HttpRequestUtil {
    private static final Logger LOG = LoggerFactory.getLogger(HttpRequestUtil.class);

    public static void logDebug(HttpServletRequest aRequest) {
        if(!LOG.isDebugEnabled()) return;

        String name = aRequest.getHeader("nginx_location");
        LOG.debug("{} - {}", name , createUriAndQuery(aRequest));

        Enumeration<String> headers = aRequest.getHeaderNames();
        LOG.debug("    headers:");
        while (headers.hasMoreElements()) {
            String header = headers.nextElement();
            LOG.debug("        {} = {}", header, redactHeader(header, aRequest.getHeader(header)));
        }
        Enumeration<String> parameters = aRequest.getParameterNames();
        LOG.debug("    parameters:");
        while (parameters.hasMoreElements()) {
            String parameter = parameters.nextElement();
            LOG.debug("        {} = {}", parameter, redactParameter(parameter, aRequest.getParameter(parameter)));
        }

    }

    public static void setNoStoreHeaders(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setContentType("text/html; charset=UTF-8");
    }

    public static String clientIp(HttpServletRequest request) {
        String headerName = SettingsManager.getClientIpHeader();
        if (hasText(headerName)) {
            String headerValue = request.getHeader(headerName);
            if (hasText(headerValue)) {
                int comma = headerValue.indexOf(',');
                return comma < 0 ? headerValue.trim() : headerValue.substring(0, comma).trim();
            }
        }
        return request.getRemoteAddr();
    }

    static String redactHeader(String name, String value) {
        if (name == null) {
            return value;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        if ("authorization".equals(lower) || "cookie".equals(lower) || "set-cookie".equals(lower)) {
            return "***";
        }
        return value;
    }

    static String redactParameter(String name, String value) {
        if (name == null) {
            return value;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        if ("j_password".equals(lower)
                || "j_password_new_1".equals(lower)
                || "j_password_new_2".equals(lower)
                || "j_code".equals(lower)) {
            return "***";
        }
        String tokenCookie = SettingsManager.getTokenCookieName();
        if (tokenCookie != null && tokenCookie.equalsIgnoreCase(name)) {
            return "***";
        }
        return value;
    }

    private static String createUriAndQuery(HttpServletRequest aRequest) {
        StringBuilder sb = new StringBuilder();
        sb.append(aRequest.getRequestURI());
        String queryString = aRequest.getQueryString();
        if(queryString!=null) {
            sb.append(queryString);
        }
        return sb.toString();
    }


}
