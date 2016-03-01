package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.ITokenManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 */
public class TokenManagerImpl implements ITokenManager {
    private static final Logger LOG = LoggerFactory.getLogger(TokenManagerImpl.class);

    private static final TokenManagerImpl INSTANCE = new TokenManagerImpl();

    private TokenManagerImpl() {
    }

    public static TokenManagerImpl getInstance() {
        return INSTANCE;
    }

    @Override
    public String createToken() {
        theLock.writeLock().lock();
        try {

            if (theMap.size() > 100) {
                Iterator<Token> tokens = theMap.values().iterator();
                while (tokens.hasNext()) {
                    Token token = tokens.next();
                    if (!isValid(token)) {
                        LOG.info("Removing token {}", token.id);
                        tokens.remove();
                    }
                }
            }

            Token token = new Token();
            token.lastAccessTime = System.currentTimeMillis();
            String key = UUID.randomUUID().toString();
            token.id = key;
            theMap.put(key, token);
            LOG.info("Added token {}", key);
            return key;
        } finally {
            theLock.writeLock().unlock();
        }
    }

    @Override
    public boolean validateToken(String aTokenValue) {

        Token token;
        theLock.readLock().lock();
        try {
            token = theMap.get(aTokenValue);
            if (token == null) {
                LOG.info("Token {} not found", aTokenValue);
                LOG.info("Tokens  {}", theMap);
                return false;
            }
        } finally {
            theLock.readLock().unlock();
        }


        if (isValid(token)) {
            theLock.writeLock().lock();
            try {
                theMap.remove(aTokenValue);
                return false;
            } finally {
                theLock.writeLock().unlock();
            }
        } else {
            token.lastAccessTime = System.currentTimeMillis();
            return true;
        }
    }

    public boolean isValid(Token aToken) {
        long currentTime = System.currentTimeMillis();
        long minTime = currentTime - (15 * 1000 * 60);
        boolean valid = aToken.lastAccessTime < minTime;
        LOG.info("Token {} [time: {}] is {}", new Object[]{aToken.id, aToken.lastAccessTime, valid ? "valid" : "not valid"});
        return valid;
    }

    private static class Token {
        private String id;
        private long lastAccessTime;
    }

    private ReentrantReadWriteLock theLock = new ReentrantReadWriteLock();
    private final Map<String, Token> theMap = new HashMap<String, Token>();
}
