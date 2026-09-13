package com.payneteasy.nginxauth.service.impl;

import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class OneTimePasswordServiceImplTest {

    private static final String SECRET = "JBSWY3DPEHPK3PXP";

    @Test
    public void replayOfSameCodeIsRejected() {
        Map<String, String> secrets = new HashMap<String, String>();
        secrets.put("alice", SECRET);
        AtomicLong now = new AtomicLong(1_700_000_000_000L);
        OneTimePasswordServiceImpl service = newService(secrets, now);

        int code = service.codeAt(SECRET, now.get());
        assertTrue(service.checkCode("alice", code));
        assertFalse(service.checkCode("alice", code));
    }

    @Test
    public void unknownUserIsRejected() {
        OneTimePasswordServiceImpl service = newService(Collections.<String, String>emptyMap(), new AtomicLong(1_700_000_000_000L));
        assertFalse(service.checkCode("nobody", 123456L));
    }

    @Test
    public void unknownUserAndBadCodeBothRunHmac() {
        Map<String, String> secrets = new HashMap<String, String>();
        secrets.put("alice", SECRET);
        AtomicLong now = new AtomicLong(1_700_000_000_000L);
        CountingAuthenticator authenticator = new CountingAuthenticator();
        OneTimePasswordServiceImpl service = new OneTimePasswordServiceImpl(
                new OtpSecretStore(secrets, SECRET),
                now::get,
                authenticator
        );

        assertFalse(service.checkCode("nobody", 123456L));
        int afterUnknown = authenticator.checks.get();
        assertEquals(1, afterUnknown);

        assertFalse(service.checkCode("alice", 123456L));
        assertEquals(2, authenticator.checks.get());
    }

    private static OneTimePasswordServiceImpl newService(Map<String, String> secrets, AtomicLong now) {
        return new OneTimePasswordServiceImpl(
                new OtpSecretStore(secrets, SECRET),
                now::get,
                new GoogleAuthenticator()
        );
    }

    private static final class CountingAuthenticator extends GoogleAuthenticator {
        private final AtomicInteger checks = new AtomicInteger();

        @Override
        public boolean check_code(String secret, long code, long timeMsec) {
            checks.incrementAndGet();
            return super.check_code(secret, code, timeMsec);
        }
    }
}
