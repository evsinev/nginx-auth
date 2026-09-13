package com.payneteasy.nginxauth.service.impl;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class TokenManagerImplTest {

    @Test
    public void createAndValidate() {
        TokenManagerImpl manager = new TokenManagerImpl(15 * 60 * 1000L, System::currentTimeMillis);
        String token = manager.createToken("alice");
        assertNotNull(token);
        assertTrue(manager.validateToken(token));
        assertTrue(manager.validateToken(token));
    }

    @Test
    public void expiredTokenIsRejectedAndRemoved() {
        AtomicLong now = new AtomicLong(1_000_000L);
        TokenManagerImpl manager = new TokenManagerImpl(1_000L, now::get);
        String token = manager.createToken("alice");
        assertTrue(manager.validateToken(token));
        now.addAndGet(1_001L);
        assertFalse(manager.validateToken(token));
        assertEquals(0, manager.size());
        assertFalse(manager.validateToken(token));
    }

    @Test
    public void liveTokensRemainWhenManyCreated() {
        TokenManagerImpl manager = new TokenManagerImpl(15 * 60 * 1000L, System::currentTimeMillis);
        String[] tokens = new String[101];
        for (int i = 0; i < tokens.length; i++) {
            tokens[i] = manager.createToken("user" + i);
        }
        assertEquals(101, manager.size());
        for (String token : tokens) {
            assertTrue(manager.validateToken(token));
        }
    }

    @Test
    public void invalidateToken() {
        TokenManagerImpl manager = new TokenManagerImpl(15 * 60 * 1000L, System::currentTimeMillis);
        String token = manager.createToken("alice");
        manager.invalidateToken(token);
        assertFalse(manager.validateToken(token));
    }

    @Test
    public void nullTokenIsRejected() {
        TokenManagerImpl manager = new TokenManagerImpl(15 * 60 * 1000L, System::currentTimeMillis);
        assertFalse(manager.validateToken(null));
    }
}
