package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.AuthenticationMethod;
import com.payneteasy.nginxauth.service.ITokenManager;
import com.payneteasy.nginxauth.service.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.LongSupplier;
import java.util.function.Predicate;

public class TokenManagerImpl implements ITokenManager {
    private static final Logger LOG = LoggerFactory.getLogger(TokenManagerImpl.class);

    private static final long DEFAULT_INACTIVITY_MILLIS = 15 * 60 * 1000L;

    private static final TokenManagerImpl INSTANCE = new TokenManagerImpl();

    private TokenManagerImpl() {
        this(DEFAULT_INACTIVITY_MILLIS, System::currentTimeMillis);
    }

    public TokenManagerImpl(long inactivityMillis, LongSupplier clock) {
        this.inactivityMillis = inactivityMillis;
        this.clock = clock;
    }

    public static TokenManagerImpl getInstance() {
        return INSTANCE;
    }

    @Override
    public String createToken(String username) {
        return createSession(Session.withoutWebAuthn(username, username, Collections.emptyList(), AuthenticationMethod.LDAP_ONLY, clock.getAsLong())
                .withLogin(username, 0L));
    }

    @Override
    public String createSession(Session aSession) {
        theLock.writeLock().lock();
        try {
            removeExpired();
            String key = put(aSession);
            LOG.debug("Session created for user {} with {}", aSession.getCanonicalUid(), aSession.getMethod());
            return key;
        } finally {
            theLock.writeLock().unlock();
        }
    }

    @Override
    public boolean validateToken(String aTokenValue) {
        return getSession(aTokenValue).isPresent();
    }

    @Override
    public Optional<Session> getSession(String aTokenValue) {
        return lookup(aTokenValue, true);
    }

    @Override
    public Optional<Session> peekSession(String aTokenValue) {
        return lookup(aTokenValue, false);
    }

    @Override
    public Optional<String> replaceIfActive(String aOldToken, Session aNewSession) {
        if (aOldToken == null) {
            return Optional.empty();
        }
        theLock.writeLock().lock();
        try {
            Token old = theMap.get(aOldToken);
            if (old == null) {
                return Optional.empty();
            }
            theMap.remove(aOldToken);
            if (isExpired(old)) {
                return Optional.empty();
            }
            return Optional.of(put(aNewSession));
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

    @Override
    public void invalidateUser(String aCanonicalUid) {
        removeIf(session -> aCanonicalUid.equals(session.getCanonicalUid()));
    }

    @Override
    public void invalidateByCredential(String aCanonicalUid, String aCredentialId) {
        removeIf(session -> aCanonicalUid.equals(session.getCanonicalUid()) && aCredentialId.equals(session.getCredentialId()));
    }

    @Override
    public void invalidateByBrowserBinding(String aBrowserBinding) {
        if (aBrowserBinding == null) {
            return;
        }
        removeIf(session -> aBrowserBinding.equals(session.getBrowserBinding()));
    }

    @Override
    public void invalidateByLoginName(String aLoginName) {
        if (aLoginName == null) {
            return;
        }
        removeIf(session -> aLoginName.equalsIgnoreCase(session.getLoginName()));
    }

    int size() {
        theLock.readLock().lock();
        try {
            return theMap.size();
        } finally {
            theLock.readLock().unlock();
        }
    }

    private Optional<Session> lookup(String aTokenValue, boolean touch) {
        if (aTokenValue == null) {
            return Optional.empty();
        }

        Token token;
        theLock.readLock().lock();
        try {
            token = theMap.get(aTokenValue);
        } finally {
            theLock.readLock().unlock();
        }

        if (token == null) {
            return Optional.empty();
        }

        theLock.writeLock().lock();
        try {
            if (theMap.get(aTokenValue) != token) {
                return Optional.empty();
            }
            if (isExpired(token)) {
                theMap.remove(aTokenValue);
                return Optional.empty();
            }
            if (touch) {
                token.lastAccessTime = clock.getAsLong();
            }
            return Optional.of(token.session);
        } finally {
            theLock.writeLock().unlock();
        }
    }

    private String put(Session aSession) {
        Token token = new Token();
        token.lastAccessTime = clock.getAsLong();
        token.session = aSession;
        String key = UUID.randomUUID().toString();
        theMap.put(key, token);
        return key;
    }

    private void removeIf(Predicate<Session> aPredicate) {
        theLock.writeLock().lock();
        try {
            theMap.values().removeIf(token -> aPredicate.test(token.session));
        } finally {
            theLock.writeLock().unlock();
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
        private Session session;
        private long lastAccessTime;
    }

    private final long inactivityMillis;
    private final LongSupplier clock;
    private final ReentrantReadWriteLock theLock = new ReentrantReadWriteLock();
    private final Map<String, Token> theMap = new HashMap<String, Token>();
}
