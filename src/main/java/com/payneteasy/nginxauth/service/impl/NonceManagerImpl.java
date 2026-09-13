package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.INonceManager;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

public class NonceManagerImpl implements INonceManager {

    private static final long DEFAULT_TTL_MILLIS = 10 * 60 * 1000L;
    private static final int DEFAULT_CAP = 10_000;

    private static final NonceManagerImpl INSTANCE = new NonceManagerImpl();

    public static INonceManager getInstance() {
        return INSTANCE;
    }

    private NonceManagerImpl() {
        this(DEFAULT_TTL_MILLIS, DEFAULT_CAP, System::currentTimeMillis);
    }

    NonceManagerImpl(long ttlMillis, int cap, LongSupplier clock) {
        this.ttlMillis = ttlMillis;
        this.cap = cap;
        this.clock = clock;
    }

    @Override
    public String addNonce() {
        long now = clock.getAsLong();
        purgeExpired(now);
        if (nonces.size() >= cap) {
            purgeExpired(now);
            if (nonces.size() >= cap) {
                return null;
            }
        }
        String key = UUID.randomUUID().toString();
        nonces.put(key, now + ttlMillis);
        return key;
    }

    @Override
    public boolean checkNonce(String aNonce) {
        if (aNonce == null) {
            return false;
        }
        Long expiresAt = nonces.remove(aNonce);
        if (expiresAt == null) {
            return false;
        }
        return expiresAt > clock.getAsLong();
    }

    int size() {
        return nonces.size();
    }

    private void purgeExpired(long now) {
        nonces.entrySet().removeIf(entry -> entry.getValue() <= now);
    }

    private final long ttlMillis;
    private final int cap;
    private final LongSupplier clock;
    private final ConcurrentHashMap<String, Long> nonces = new ConcurrentHashMap<String, Long>();
}
