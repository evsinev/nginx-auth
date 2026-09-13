package com.payneteasy.nginxauth.util;

import java.net.URI;
import java.util.Optional;

public final class BackUrl {

    private BackUrl() {
    }

    public static Optional<String> normalize(String raw) {
        if (raw == null || raw.isEmpty()) {
            return Optional.empty();
        }
        if (!raw.startsWith("/")) {
            return Optional.empty();
        }
        if (raw.startsWith("//") || raw.startsWith("/\\")) {
            return Optional.empty();
        }
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '\\' || Character.isISOControl(c)) {
                return Optional.empty();
            }
        }
        try {
            URI uri = URI.create(raw);
            if (uri.getScheme() != null || uri.getRawAuthority() != null) {
                return Optional.empty();
            }
            return Optional.of(raw);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
