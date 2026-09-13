package com.payneteasy.nginxauth.service.impl;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class NonceManagerImplTest {

    @Test
    public void oneShot() {
        NonceManagerImpl manager = new NonceManagerImpl(10_000L, 100, System::currentTimeMillis);
        String nonce = manager.addNonce();
        assertNotNull(nonce);
        assertTrue(manager.checkNonce(nonce));
        assertFalse(manager.checkNonce(nonce));
    }

    @Test
    public void expiredNonceIsRejected() {
        AtomicLong now = new AtomicLong(1_000L);
        NonceManagerImpl manager = new NonceManagerImpl(100L, 100, now::get);
        String nonce = manager.addNonce();
        now.addAndGet(101L);
        assertFalse(manager.checkNonce(nonce));
    }

    @Test
    public void capRefusesNewNonceAfterPurge() {
        AtomicLong now = new AtomicLong(1_000L);
        NonceManagerImpl manager = new NonceManagerImpl(10_000L, 2, now::get);
        assertNotNull(manager.addNonce());
        assertNotNull(manager.addNonce());
        assertEquals(2, manager.size());
        assertNull(manager.addNonce());
        assertEquals(2, manager.size());
    }

    @Test
    public void capAllowsIssueAfterExpiry() {
        AtomicLong now = new AtomicLong(1_000L);
        NonceManagerImpl manager = new NonceManagerImpl(50L, 2, now::get);
        assertNotNull(manager.addNonce());
        assertNotNull(manager.addNonce());
        now.addAndGet(51L);
        assertNotNull(manager.addNonce());
        assertEquals(1, manager.size());
    }
}
