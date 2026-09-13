package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.ITokenManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.LongSupplier;

public class TokenManagerImpl implements ITokenManager {
    private static final Logger LOG = LoggerFactory.getLogger(TokenManagerImpl.class);

    private static final long DEFAULT_INACTIVITY_MILLIS = 15 * 60 * 1000L;

    private static final TokenManagerImpl INSTANCE = new TokenManagerImpl();

    private TokenManagerImpl() {
        this(DEFAULT_INACTIVITY_MILLIS, System::currentTimeMillis);
    }

    TokenManagerImpl(long inactivityMillis, LongSupplier clock) {
        this.inactivityMillis = inactivityMillis;
        this.clock = clock;
    }

    public static TokenManagerImpl getInstance() {
        return INSTANCE;
    }

    @Override
    public String createToken(String username) {
        theLock.writeLock().lock();
        try {
            removeExpired();

            Token token = new Token();
            token.lastAccessTime = clock.getAsLong();
            token.username = username;
            String key = UUID.randomUUID().toString();
            token.id = key;
            theMap.put(key, token);
            LOG.debug("Token created for user {}", username);
            return key;
        } finally {
            theLock.writeLock().unlock();
        }
    }

    @Override
    public boolean validateToken(String aTokenValue) {
        if (aTokenValue == null) {
            return false;
        }

        Token token;
        theLock.readLock().lock();
        try {
            token = theMap.get(aTokenValue);
        } finally {
            theLock.readLock().unlock();
        }

        if (token == null) {
            return false;
        }

        if (isExpired(token)) {
            theLock.writeLock().lock();
            try {
                theMap.remove(aTokenValue);
                return false;
            } finally {
                theLock.writeLock().unlock();
            }
        }

        theLock.writeLock().lock();
        try {
            token.lastAccessTime = clock.getAsLong();
            return true;
        } finally {
            theLock.writeLock().unlock();
        }
    }

    @Override
    public void invalidateToken(String aTokenValue) {
        if (aTokenValue == null) {
            return;
        }
        theLock.writeLock().lock();
        try {
            theMap.remove(aTokenValue);
        } finally {
            theLock.writeLock().unlock();
        }
    }

    int size() {
        theLock.readLock().lock();
        try {
            return theMap.size();
        } finally {
            theLock.readLock().unlock();
        }
    }

    private void removeExpired() {
        Iterator<Token> tokens = theMap.values().iterator();
        while (tokens.hasNext()) {
            Token token = tokens.next();
            if (isExpired(token)) {
                tokens.remove();
            }
        }
    }

    boolean isExpired(Token aToken) {
        return aToken.lastAccessTime < clock.getAsLong() - inactivityMillis;
    }

    static class Token {
        private String id;
        private String username;
        private long lastAccessTime;
    }

    private final long inactivityMillis;
    private final LongSupplier clock;
    private final ReentrantReadWriteLock theLock = new ReentrantReadWriteLock();
    private final Map<String, Token> theMap = new HashMap<String, Token>();
}
