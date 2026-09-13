package com.payneteasy.nginxauth.service.impl;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RateLimiterTest {

    @Test
    public void blocksAfterMaxFailuresAndAllowsAfterWindow() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = new RateLimiter(5, 300_000L, now::get);
        String key = RateLimiter.userKey("alice");

        for (int i = 0; i < 5; i++) {
            assertFalse(limiter.isBlocked(key));
            limiter.recordFailure(key);
        }
        assertTrue(limiter.isBlocked(key));

        now.addAndGet(300_000L);
        assertFalse(limiter.isBlocked(key));
    }

    @Test
    public void successClearsFailures() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = new RateLimiter(5, 300_000L, now::get);
        String key = RateLimiter.userKey("alice");
        for (int i = 0; i < 5; i++) {
            limiter.recordFailure(key);
        }
        assertTrue(limiter.isBlocked(key));
        limiter.recordSuccess(key);
        assertFalse(limiter.isBlocked(key));
    }
}
