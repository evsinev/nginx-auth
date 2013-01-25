package com.payneteasy.nginxauth.util;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

public class HttpRequestUtil {
    private static final Logger LOG = LoggerFactory.getLogger(HttpRequestUtil.class);

    public static void logDebug(HttpServletRequest aRequest) {
        if(!LOG.isDebugEnabled()) return;

        String name = aRequest.getHeader("nginx_location");
        LOG.debug("{} - {}", name , createUriAndQuery(aRequest));

        Enumeration<String> headers = aRequest.getHeaderNames();
        LOG.info("    headers:");
        while (headers.hasMoreElements()) {
            String header = headers.nextElement();
            LOG.debug("        {} = {}", header, aRequest.getHeader(header));
        }
        Enumeration<String> parameters = aRequest.getParameterNames();
        LOG.info("    parameters:");
        while (parameters.hasMoreElements()) {
            String parameter = parameters.nextElement();
            LOG.debug("        {} = {}", parameter, aRequest.getParameter(parameter));
        }

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
