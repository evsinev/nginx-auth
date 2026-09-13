package com.payneteasy.nginxauth.service.impl;

import org.junit.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class RateLimiterTest {

    @Test
    public void credentialScheduleThenThrottle() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = defaultLimiter(now);

        RateLimiter.Attempt first = limiter.begin("1.1.1.1", "alice");
        assertFalse(first.denied());
        assertEquals(0L, first.delayMillis());
        first.failed();

        RateLimiter.Attempt second = limiter.begin("1.1.1.1", "alice");
        assertFalse(second.denied());
        assertEquals(2_000L, second.delayMillis());
        second.failed();

        RateLimiter.Attempt third = limiter.begin("1.1.1.1", "alice");
        assertTrue(third.denied());
        assertEquals(0L, third.delayMillis());

        RateLimiter.Attempt fourth = limiter.begin("1.1.1.1", "alice");
        assertTrue(fourth.denied());

        now.addAndGet(300_000L);
        RateLimiter.Attempt fifth = limiter.begin("1.1.1.1", "alice");
        assertFalse(fifth.denied());
        assertEquals(0L, fifth.delayMillis());
        fifth.failed();

        RateLimiter.Attempt sixth = limiter.begin("1.1.1.1", "alice");
        assertTrue(sixth.denied());
    }

    @Test
    public void delayIsNotDeny() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = defaultLimiter(now);
        limiter.begin("1.1.1.1", "alice").failed();
        RateLimiter.Attempt attempt = limiter.begin("1.1.1.1", "alice");
        assertFalse(attempt.denied());
        assertEquals(2_000L, attempt.delayMillis());
    }

    @Test
    public void windowExpiryClearsBucket() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = defaultLimiter(now);
        limiter.begin("1.1.1.1", "alice").failed();
        limiter.begin("1.1.1.1", "alice").failed();
        assertTrue(limiter.begin("1.1.1.1", "alice").denied());
        now.addAndGet(900_000L);
        RateLimiter.Attempt attempt = limiter.begin("1.1.1.1", "alice");
        assertFalse(attempt.denied());
        assertEquals(0L, attempt.delayMillis());
    }

    @Test
    public void rotatingIpsShareUserCounter() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = defaultLimiter(now);

        RateLimiter.Attempt first = limiter.begin("1.1.1.1", "carol");
        assertFalse(first.denied());
        first.failed();

        RateLimiter.Attempt second = limiter.begin("2.2.2.2", "carol");
        assertFalse(second.denied());
        assertEquals(2_000L, second.delayMillis());
        second.failed();

        assertTrue(limiter.begin("1.1.1.1", "carol").denied());
        assertTrue(limiter.begin("2.2.2.2", "carol").denied());
        assertTrue(limiter.begin("3.3.3.3", "carol").denied());
    }

    @Test
    public void succeededClearsUserAcrossIps() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = defaultLimiter(now);
        limiter.begin("1.1.1.1", "alice").failed();
        limiter.begin("1.1.1.1", "alice").failed();
        limiter.begin("1.1.1.1", "alice").succeeded();

        RateLimiter.Attempt sameIp = limiter.begin("1.1.1.1", "alice");
        assertFalse(sameIp.denied());
        assertEquals(0L, sameIp.delayMillis());

        RateLimiter.Attempt otherIp = limiter.begin("2.2.2.2", "alice");
        assertFalse(otherIp.denied());
        assertEquals(0L, otherIp.delayMillis());

        RateLimiter.Attempt otherUser = limiter.begin("1.1.1.1", "bob");
        assertFalse(otherUser.denied());
        assertEquals(0L, otherUser.delayMillis());
    }

    @Test
    public void ipThrottleHasNoDelay() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = defaultLimiter(now);
        for (int i = 0; i < 20; i++) {
            RateLimiter.Attempt attempt = limiter.begin("1.1.1.1", "user" + i);
            assertFalse("attempt " + i, attempt.denied());
            assertEquals(0L, attempt.delayMillis());
            attempt.failed();
        }
        RateLimiter.Attempt blocked = limiter.begin("1.1.1.1", "user20");
        assertTrue(blocked.denied());
        assertEquals(0L, blocked.delayMillis());

        RateLimiter.Attempt otherIp = limiter.begin("9.9.9.9", "user20");
        assertFalse(otherIp.denied());
        assertEquals(0L, otherIp.delayMillis());
    }

    @Test
    public void nullIpUsesUserOnly() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = defaultLimiter(now);
        limiter.begin(null, "alice").failed();
        limiter.begin(null, "alice").failed();
        RateLimiter.Attempt third = limiter.begin(null, "alice");
        assertTrue(third.denied());
        third.succeeded();
        RateLimiter.Attempt afterSuccess = limiter.begin(null, "alice");
        assertFalse(afterSuccess.denied());
        assertEquals(0L, afterSuccess.delayMillis());
    }

    @Test
    public void semaphoreDeniesWhenFull() throws Exception {
        AtomicLong now = new AtomicLong(1_000L);
        CountDownLatch inSleep = new CountDownLatch(1);
        CountDownLatch finishSleep = new CountDownLatch(1);
        RateLimiter limiter = new RateLimiter(
                2, 20, new int[] {0, 2}, 300_000L, 900_000L, 1, now::get,
                millis -> {
                    inSleep.countDown();
                    if (!finishSleep.await(5, TimeUnit.SECONDS)) {
                        throw new InterruptedException("sleeper timeout");
                    }
                }
        );
        limiter.begin("1.1.1.1", "alice").failed();
        RateLimiter.Attempt first = limiter.begin("1.1.1.1", "alice");
        assertEquals(2_000L, first.delayMillis());
        Thread sleeper = new Thread(first::awaitDelay);
        sleeper.start();
        assertTrue(inSleep.await(5, TimeUnit.SECONDS));

        RateLimiter.Attempt second = limiter.begin("1.1.1.1", "alice");
        assertEquals(2_000L, second.delayMillis());
        second.awaitDelay();
        assertTrue(second.denied());

        finishSleep.countDown();
        sleeper.join(5_000L);
        assertFalse(first.denied());
    }

    @Test
    public void parseDelays() {
        assertArrayEquals(new int[] {0, 2}, RateLimiter.parseDelays("0,2"));
        assertArrayEquals(new int[] {0}, RateLimiter.parseDelays(""));
        assertArrayEquals(new int[] {5}, RateLimiter.parseDelays("5"));
        try {
            RateLimiter.parseDelays("a,b");
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException ignored) {
        }
        try {
            RateLimiter.parseDelays("-1");
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException ignored) {
        }
    }

    @Test
    public void rejectsZeroThresholds() {
        AtomicLong now = new AtomicLong(1_000L);
        try {
            new RateLimiter(0, 20, new int[] {0}, 300_000L, 900_000L, 32, now::get, millis -> {});
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException ignored) {
        }
        try {
            new RateLimiter(2, 0, new int[] {0}, 300_000L, 900_000L, 32, now::get, millis -> {});
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException ignored) {
        }
    }

    @Test
    public void maxFailuresWithSingleZeroDelay() {
        AtomicLong now = new AtomicLong(1_000L);
        RateLimiter limiter = new RateLimiter(
                2, 20, new int[] {0}, 300_000L, 900_000L, 32, now::get, millis -> {}
        );
        RateLimiter.Attempt first = limiter.begin("1.1.1.1", "alice");
        assertEquals(0L, first.delayMillis());
        first.failed();
        RateLimiter.Attempt second = limiter.begin("1.1.1.1", "alice");
        assertFalse(second.denied());
        assertEquals(0L, second.delayMillis());
        second.failed();
        assertTrue(limiter.begin("1.1.1.1", "alice").denied());
    }

    private static RateLimiter defaultLimiter(AtomicLong now) {
        return new RateLimiter(
                2, 20, new int[] {0, 2}, 300_000L, 900_000L, 32, now::get, millis -> {}
        );
    }
}
