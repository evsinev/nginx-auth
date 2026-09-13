package com.payneteasy.nginxauth.service.impl;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
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
    public void expiredWindowsArePurged() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = new RateLimiter(5, 300_000L, now::get);
        for (int i = 0; i < 20; i++) {
            limiter.recordFailure(RateLimiter.userKey("u" + i));
        }
        assertEquals(20, limiter.size());
        now.addAndGet(300_000L);
        limiter.recordFailure(RateLimiter.userKey("fresh"));
        assertEquals(1, limiter.size());
    }

    @Test
    public void nullKeyIsIgnored() {
        RateLimiter limiter = new RateLimiter(5, 300_000L, System::currentTimeMillis);
        limiter.recordFailure(null);
        assertFalse(limiter.isBlocked(null));
        limiter.recordSuccess(null);
        assertEquals(0, limiter.size());
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
