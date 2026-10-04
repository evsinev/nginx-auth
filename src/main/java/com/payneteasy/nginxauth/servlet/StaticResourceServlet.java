package com.payneteasy.nginxauth.servlet;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

/**
 * Serves a fixed set of static files from the classpath.
 */
public class StaticResourceServlet extends HttpServlet {

    private static final Map<String, String> FILES = Map.of(
            "/webauthn.js", "application/javascript; charset=UTF-8"
    );

    @Override
    protected void doGet(HttpServletRequest aRequest, HttpServletResponse aResponse) throws IOException {
        String path = aRequest.getPathInfo();
        String contentType = path == null ? null : FILES.get(path);
        if (contentType == null) {
            aResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        try (InputStream in = StaticResourceServlet.class.getResourceAsStream("/static" + path)) {
            if (in == null) {
                aResponse.sendError(HttpServletResponse.SC_NOT_FOUND);
                return;
            }
            aResponse.setContentType(contentType);
            aResponse.setHeader("Cache-Control", "no-cache");
            aResponse.setHeader("X-Content-Type-Options", "nosniff");
            in.transferTo(aResponse.getOutputStream());
        }
    }
}
