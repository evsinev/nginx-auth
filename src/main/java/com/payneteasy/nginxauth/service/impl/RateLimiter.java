package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.util.SettingsManager;

import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.function.LongSupplier;

public class RateLimiter {

    public interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    private static final long PURGE_INTERVAL_MILLIS = 30_000L;

    private static final RateLimiter INSTANCE = new RateLimiter(
            SettingsManager.getLoginMaxFailures(),
            SettingsManager.getLoginIpMaxFailures(),
            parseDelays(SettingsManager.getLoginDelaysSeconds()),
            SettingsManager.getLoginLockoutSeconds() * 1000L,
            SettingsManager.getLoginFailureWindowSeconds() * 1000L,
            SettingsManager.getLoginMaxConcurrentDelays(),
            System::currentTimeMillis,
            Thread::sleep
    );

    public static RateLimiter getInstance() {
        return INSTANCE;
    }

    private final int maxFailures;
    private final int ipMaxFailures;
    private final int[] delaysSeconds;
    private final long lockoutMillis;
    private final long failureWindowMillis;
    private final LongSupplier clock;
    private final Sleeper sleeper;
    private final Semaphore delaySlots;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<String, Bucket>();
    private volatile long lastPurgeAt;

    RateLimiter(
            int maxFailures,
            int ipMaxFailures,
            int[] delaysSeconds,
            long lockoutMillis,
            long failureWindowMillis,
            int maxConcurrentDelays,
            LongSupplier clock,
            Sleeper sleeper
    ) {
        if (maxFailures < 1) {
            throw new IllegalArgumentException("LOGIN_MAX_FAILURES must be >= 1");
        }
        if (ipMaxFailures < 1) {
            throw new IllegalArgumentException("LOGIN_IP_MAX_FAILURES must be >= 1");
        }
        if (maxConcurrentDelays < 1) {
            throw new IllegalArgumentException("LOGIN_MAX_CONCURRENT_DELAYS must be >= 1");
        }
        this.maxFailures = maxFailures;
        this.ipMaxFailures = ipMaxFailures;
        this.delaysSeconds = Arrays.copyOf(delaysSeconds, delaysSeconds.length);
        this.lockoutMillis = lockoutMillis;
        this.failureWindowMillis = failureWindowMillis;
        this.clock = clock;
        this.sleeper = sleeper;
        this.delaySlots = new Semaphore(maxConcurrentDelays);
    }

    public Attempt begin(String ip, String username) {
        long now = clock.getAsLong();
        purgeExpired(now);

        String userKey = userKey(username);
        String ipKey = ip == null ? null : ipKey(ip);
        String pairKey = ip == null ? null : pairKey(ip, username);

        Bucket pair = live(pairKey, now);
        Bucket cred = pair != null ? pair : live(userKey, now);
        int credFailures = cred == null ? 0 : cred.failures;
        long credLastFailureAt = cred == null ? 0L : cred.lastFailureAt;

        Bucket ipBucket = live(ipKey, now);
        int ipFailures = ipBucket == null ? 0 : ipBucket.failures;
        long ipLastFailureAt = ipBucket == null ? 0L : ipBucket.lastFailureAt;

        boolean denied = false;
        if (credFailures >= maxFailures && now - credLastFailureAt < lockoutMillis) {
            denied = true;
        }
        if (ipFailures >= ipMaxFailures && now - ipLastFailureAt < lockoutMillis) {
            denied = true;
        }

        long delayMillis = 0L;
        if (!denied && credFailures < maxFailures) {
            delayMillis = delayMillisFor(credFailures);
        }

        return new Attempt(ip, username, denied, delayMillis);
    }

    public final class Attempt {
        private final String ip;
        private final String username;
        private boolean denied;
        private final long delayMillis;

        private Attempt(String ip, String username, boolean denied, long delayMillis) {
            this.ip = ip;
            this.username = username;
            this.denied = denied;
            this.delayMillis = delayMillis;
        }

        public boolean denied() {
            return denied;
        }

        public long delayMillis() {
            return delayMillis;
        }

        public void awaitDelay() {
            if (denied || delayMillis <= 0L) {
                return;
            }
            if (!delaySlots.tryAcquire()) {
                denied = true;
                return;
            }
            try {
                sleeper.sleep(delayMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                denied = true;
            } finally {
                delaySlots.release();
            }
        }

        public void failed() {
            recordFailure(ip, username);
        }

        public void succeeded() {
            recordSuccess(ip, username);
        }
    }

    static int[] parseDelays(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return new int[] { 0 };
        }
        String[] parts = raw.split(",", -1);
        int[] delays = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i].trim();
            if (part.isEmpty()) {
                throw new IllegalArgumentException("LOGIN_DELAYS_SECONDS must be a comma-separated list of non-negative integers");
            }
            final int value;
            try {
                value = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("LOGIN_DELAYS_SECONDS must be a comma-separated list of non-negative integers", e);
            }
            if (value < 0) {
                throw new IllegalArgumentException("LOGIN_DELAYS_SECONDS must be a comma-separated list of non-negative integers");
            }
            delays[i] = value;
        }
        return delays;
    }

    int size() {
        return buckets.size();
    }

    private void recordFailure(String ip, String username) {
        long now = clock.getAsLong();
        bump(userKey(username), now);
        if (ip != null) {
            bump(ipKey(ip), now);
            bump(pairKey(ip, username), now);
        }
    }

    private void recordSuccess(String ip, String username) {
        if (ip == null) {
            return;
        }
        buckets.put(pairKey(ip, username), new Bucket(0, clock.getAsLong()));
    }

    private void bump(String key, long now) {
        buckets.compute(key, (k, bucket) -> {
            if (bucket == null || now - bucket.lastFailureAt >= failureWindowMillis) {
                return new Bucket(1, now);
            }
            return new Bucket(bucket.failures + 1, now);
        });
    }

    private Bucket live(String key, long now) {
        if (key == null) {
            return null;
        }
        Bucket bucket = buckets.get(key);
        if (bucket == null) {
            return null;
        }
        if (now - bucket.lastFailureAt >= failureWindowMillis) {
            buckets.remove(key, bucket);
            return null;
        }
        return bucket;
    }

    private long delayMillisFor(int failures) {
        if (delaysSeconds.length == 0) {
            return 0L;
        }
        int index = Math.min(failures, delaysSeconds.length - 1);
        return delaysSeconds[index] * 1000L;
    }

    private void purgeExpired(long now) {
        if (now - lastPurgeAt < PURGE_INTERVAL_MILLIS) {
            return;
        }
        lastPurgeAt = now;
        buckets.entrySet().removeIf(entry -> now - entry.getValue().lastFailureAt >= failureWindowMillis);
    }

    private static String userKey(String username) {
        return "user:" + username;
    }

    private static String ipKey(String ip) {
        return "ip:" + ip;
    }

    private static String pairKey(String ip, String username) {
        return "pair:" + ip + "|" + username;
    }

    private static final class Bucket {
        private final int failures;
        private final long lastFailureAt;

        private Bucket(int failures, long lastFailureAt) {
            this.failures = failures;
            this.lastFailureAt = lastFailureAt;
        }
    }
}
