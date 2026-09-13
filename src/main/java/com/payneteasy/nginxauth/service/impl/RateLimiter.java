package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.util.SettingsManager;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

public class RateLimiter {

    private static final RateLimiter INSTANCE = new RateLimiter(
            SettingsManager.getLoginMaxFailures(),
            SettingsManager.getLoginLockoutSeconds() * 1000L,
            System::currentTimeMillis
    );

    public static RateLimiter getInstance() {
        return INSTANCE;
    }

    private final int maxFailures;
    private final long lockoutMillis;
    private final LongSupplier clock;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<String, Window>();

    RateLimiter(int maxFailures, long lockoutMillis, LongSupplier clock) {
        this.maxFailures = maxFailures;
        this.lockoutMillis = lockoutMillis;
        this.clock = clock;
    }

    public static String userKey(String username) {
        return "user:" + username;
    }

    public static String ipKey(String ip) {
        return "ip:" + ip;
    }

    public boolean isBlocked(String key) {
        if (key == null) {
            return false;
        }
        long now = clock.getAsLong();
        purgeExpired(now);
        Window window = windows.get(key);
        if (window == null) {
            return false;
        }
        return window.failures >= maxFailures;
    }

    public void recordFailure(String key) {
        if (key == null) {
            return;
        }
        long now = clock.getAsLong();
        purgeExpired(now);
        windows.compute(key, (k, window) -> {
            if (window == null || now - window.windowStart >= lockoutMillis) {
                return new Window(1, now);
            }
            return new Window(window.failures + 1, window.windowStart);
        });
    }

    public void recordSuccess(String key) {
        if (key == null) {
            return;
        }
        windows.remove(key);
    }

    int size() {
        return windows.size();
    }

    private void purgeExpired(long now) {
        windows.entrySet().removeIf(entry -> now - entry.getValue().windowStart >= lockoutMillis);
    }

    private static final class Window {
        private final int failures;
        private final long windowStart;

        private Window(int failures, long windowStart) {
            this.failures = failures;
            this.windowStart = windowStart;
        }
    }
}
