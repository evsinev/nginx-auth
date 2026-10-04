package com.payneteasy.nginxauth.webauthn;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * One entry of WEBAUTHN_ALLOWED_ORIGINS: {@code scheme://host[:port]} only.
 */
public final class AllowedOrigin {

    private final String scheme;
    private final String host;
    private final int    port;
    private final String origin;

    private AllowedOrigin(String scheme, String host, int port) {
        this.scheme = scheme;
        this.host   = host;
        this.port   = port;
        this.origin = scheme + "://" + host + (port == defaultPort(scheme) ? "" : ":" + port);
    }

    public static AllowedOrigin parse(String aRaw) {
        String raw = aRaw.trim();
        URI uri;
        try {
            uri = new URI(raw);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid origin " + raw);
        }
        String scheme = uri.getScheme() == null ? null : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!"https".equals(scheme) && !"http".equals(scheme)) {
            throw new IllegalArgumentException("Origin must be https: " + raw);
        }
        if (uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || (uri.getRawPath() != null && !uri.getRawPath().isEmpty())) {
            throw new IllegalArgumentException("Origin must be scheme://host[:port] only: " + raw);
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("Origin has no host: " + raw);
        }
        host = host.toLowerCase(Locale.ROOT);
        if ("http".equals(scheme) && !"localhost".equals(host)) {
            throw new IllegalArgumentException("Origin must be https (http only for localhost): " + raw);
        }
        int port = uri.getPort() == -1 ? defaultPort(scheme) : uri.getPort();
        return new AllowedOrigin(scheme, host, port);
    }

    /**
     * Matches a Host header value ({@code host} or {@code host:port}) against this origin.
     * The scheme comes from configuration, not from the request.
     */
    public boolean matchesHostHeader(String aHostHeader) {
        if (aHostHeader == null) {
            return false;
        }
        String value = aHostHeader.trim().toLowerCase(Locale.ROOT);
        if (value.isEmpty() || value.startsWith("[")) {
            return false;
        }
        String requestHost = value;
        int requestPort = defaultPort(scheme);
        int colon = value.lastIndexOf(':');
        if (colon >= 0) {
            requestHost = value.substring(0, colon);
            try {
                requestPort = Integer.parseInt(value.substring(colon + 1));
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return host.equals(requestHost) && port == requestPort;
    }

    public boolean isUnderRpId(String aRpId) {
        String rpId = aRpId.toLowerCase(Locale.ROOT);
        return host.equals(rpId) || host.endsWith("." + rpId);
    }

    private static int defaultPort(String aScheme) {
        return "https".equals(aScheme) ? 443 : 80;
    }

    public String getOrigin() {
        return origin;
    }

    public String getHost() {
        return host;
    }

    @Override
    public String toString() {
        return origin;
    }
}
