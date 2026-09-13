package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import org.junit.Test;

import javax.naming.AuthenticationException;
import javax.naming.ldap.InitialLdapContext;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class AuthServiceImplTest {

    @Test
    public void failedBindRunsDummyCheckOnly() throws Exception {
        FakeOtp otp = new FakeOtp(true);
        AuthServiceImpl auth = new AuthServiceImpl(otp, (dn, password) -> {
            throw new AuthenticationException("invalid credentials");
        });
        try {
            auth.authenticate("alice", "bad", 123456L, false);
            fail("expected AuthenticationException");
        } catch (AuthenticationException e) {
            assertEquals("Authentication failed", e.getMessage());
        }
        assertEquals(1, otp.dummyChecks.get());
        assertEquals(0, otp.codeChecks.get());
    }

    @Test
    public void successfulBindWithBadOtpIsGenericFailure() throws Exception {
        FakeOtp otp = new FakeOtp(false);
        AuthServiceImpl auth = new AuthServiceImpl(otp, (dn, password) -> new InitialLdapContext());
        try {
            auth.authenticate("alice", "good", 123456L, false);
            fail("expected AuthenticationException");
        } catch (AuthenticationException e) {
            assertEquals("Authentication failed", e.getMessage());
        }
        assertEquals(0, otp.dummyChecks.get());
        assertEquals(1, otp.codeChecks.get());
    }

    @Test
    public void successfulBindWithGoodOtpPasses() throws Exception {
        FakeOtp otp = new FakeOtp(true);
        AuthServiceImpl auth = new AuthServiceImpl(otp, (dn, password) -> new InitialLdapContext());
        auth.authenticate("alice", "good", 123456L, false);
        assertEquals(0, otp.dummyChecks.get());
        assertEquals(1, otp.codeChecks.get());
        assertNotNull(otp.lastUsername);
        assertEquals("alice", otp.lastUsername);
    }

    private static final class FakeOtp implements IOneTimePasswordService {
        private final boolean accept;
        private final AtomicInteger dummyChecks = new AtomicInteger();
        private final AtomicInteger codeChecks = new AtomicInteger();
        private String lastUsername;

        private FakeOtp(boolean accept) {
            this.accept = accept;
        }

        @Override
        public boolean checkCode(String aUsername, long aCode) {
            lastUsername = aUsername;
            codeChecks.incrementAndGet();
            return accept;
        }

        @Override
        public void dummyCheck(long aCode) {
            dummyChecks.incrementAndGet();
        }
    }
}
