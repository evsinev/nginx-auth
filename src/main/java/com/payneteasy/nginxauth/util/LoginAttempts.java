package com.payneteasy.nginxauth.util;

import com.payneteasy.nginxauth.service.impl.RateLimiter;

import jakarta.servlet.http.HttpServletRequest;

public final class LoginAttempts {

    private LoginAttempts() {
    }

    public static RateLimiter.Attempt begin(HttpServletRequest request, String username) {
        return RateLimiter.getInstance().begin(HttpRequestUtil.clientIp(request), username);
    }
}
