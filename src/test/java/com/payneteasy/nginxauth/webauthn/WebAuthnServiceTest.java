package com.payneteasy.nginxauth.webauthn;

import com.payneteasy.nginxauth.policy.PolicySet;
import com.payneteasy.nginxauth.service.AuthenticationMethod;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.Ceremony;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.Done;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.FinishResult;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.NextCeremony;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.SessionIssued;
import com.payneteasy.nginxauth.webauthn.storage.StoredCredential;
import com.payneteasy.nginxauth.webauthn.storage.UserRecord;
import org.junit.After;
import org.junit.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static com.payneteasy.nginxauth.webauthn.WebAuthnFixture.ORIGIN;
import static com.payneteasy.nginxauth.webauthn.WebAuthnFixture.ORIGIN2;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class WebAuthnServiceTest {

    private WebAuthnFixture f;

    @After
    public void cleanup() throws Exception {
        if (f != null) {
            f.deleteAll();
        }
    }

    private static void expectFailure(String aReason, ThrowingRunnable aAction) {
        try {
            aAction.run();
            fail("expected failure " + aReason);
        } catch (WebAuthnException e) {
            assertEquals(aReason, e.reason());
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    interface ThrowingRunnable {
        void run() throws Exception;
    }

    // ------------------------------------------------------------- base flow

    @Test
    public void bootstrapThenLoginThenRestart() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);

        UserRecord record = f.repository.find("alice").orElseThrow();
        assertEquals(1, record.credentials().size());
        assertEquals(key.credentialId(), record.credentials().get(0).credentialId());

        key.signCount = 1;
        String token = f.login("alice", key);
        Session session = f.tokens.peekSession(token).orElseThrow();
        assertEquals(AuthenticationMethod.LDAP_WEBAUTHN, session.getMethod());
        assertEquals(key.credentialId(), session.getCredentialId());
        assertTrue(session.isUserVerified());

        f.restart();
        key.signCount = 2;
        f.login("alice", key);
        assertEquals(2, f.repository.find("alice").orElseThrow().credentials().get(0).signCount());
    }

    @Test
    public void credentialFromApp1WorksOnApp2() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN2);
        FinishResult result = f.service.finish(state, ORIGIN2, null, "login", ceremony.transactionId(), key.get(ceremony.publicKeyJson(), ORIGIN2), null);
        assertTrue(result instanceof SessionIssued);
    }

    @Test
    public void secondCredentialRequiresConfirmation() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator first = new SoftAuthenticator();
        f.bootstrap("alice", first);

        BrowserState state = f.browser();
        String token = f.totpSession("alice", List.of());
        Ceremony confirm = f.service.startRegister(state, ORIGIN, token);
        assertEquals("get", confirm.type());
        first.signCount = 1;
        FinishResult next = f.service.finish(state, ORIGIN, token, "register", confirm.transactionId(), first.get(confirm.publicKeyJson(), ORIGIN), null);
        Ceremony create = ((NextCeremony) next).ceremony();
        assertEquals("create", create.type());

        SoftAuthenticator second = new SoftAuthenticator();
        String response = second.create(create.publicKeyJson(), ORIGIN);
        assertTrue(f.service.finish(state, ORIGIN, token, "register", create.transactionId(), response, "second") instanceof Done);
        assertEquals(2, f.repository.find("alice").orElseThrow().credentials().size());

        // the creation transaction is single-use
        expectFailure("unknown_transaction", () -> f.service.finish(state, ORIGIN, token, "register", create.transactionId(), response, "again"));
    }

    // ------------------------------------------------------------- ceremony checks

    @Test
    public void assertionFromOtherOriginIsRejected() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);

        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        // phishing page origin inside clientData
        String response = key.get(ceremony.publicKeyJson(), "https://evil.example.net");
        expectFailure("assertion_invalid", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));

        Ceremony again = f.service.startLogin(state, ORIGIN);
        String good = key.get(again.publicKeyJson(), ORIGIN);
        // request arriving through another allowed host than the one the ceremony started on
        expectFailure("origin_mismatch", () -> f.service.finish(state, ORIGIN2, null, "login", again.transactionId(), good, null));
    }

    @Test
    public void crossOriginIsRejected() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        key.crossOrigin = true;
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        expectFailure("cross_origin", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));
    }

    @Test
    public void wrongRpIdHashIsRejected() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        key.rpIdOverride = "evil.example.net";
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        expectFailure("assertion_invalid", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));
    }

    @Test
    public void credentialOfAnotherUserIsRejected() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator alice = new SoftAuthenticator();
        SoftAuthenticator bob = new SoftAuthenticator();
        f.bootstrap("alice", alice);
        f.bootstrap("bob", bob);

        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        String response = bob.get(ceremony.publicKeyJson(), ORIGIN);
        expectFailure("assertion_invalid", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));
    }

    @Test
    public void foreignUserHandleIsRejected() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator alice = new SoftAuthenticator();
        SoftAuthenticator bob = new SoftAuthenticator();
        f.bootstrap("alice", alice);
        f.bootstrap("bob", bob);

        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        alice.userHandle = bob.userHandle;
        String response = alice.get(ceremony.publicKeyJson(), ORIGIN);
        expectFailure("assertion_invalid", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));
    }

    @Test
    public void finishFromAnotherBrowserIsRejectedAndDoesNotConsume() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        BrowserState attacker = f.browser();
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);

        expectFailure("unknown_transaction", () -> f.service.finish(attacker, ORIGIN, null, "login", ceremony.transactionId(), response, null));
        assertTrue(f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null) instanceof SessionIssued);
    }

    @Test
    public void transactionIsConsumedOnceAndFailureNeedsNewChallenge() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        key.userVerified = false;
        String bad = key.get(ceremony.publicKeyJson(), ORIGIN);
        expectFailure("assertion_invalid", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), bad, null));

        key.userVerified = true;
        String good = key.get(ceremony.publicKeyJson(), ORIGIN);
        expectFailure("unknown_transaction", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), good, null));

        Ceremony retry = f.service.startLogin(state, ORIGIN);
        assertNotEquals(ceremony.transactionId(), retry.transactionId());
        assertTrue(f.service.finish(state, ORIGIN, null, "login", retry.transactionId(), key.get(retry.publicKeyJson(), ORIGIN), null) instanceof SessionIssued);
    }

    @Test
    public void preauthTtlIsNotExtendedByRetry() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony first = f.service.startLogin(state, ORIGIN);
        f.now.addAndGet(f.config.getPreauthTtlMillis() - 1_000L);
        Ceremony second = f.service.startLogin(state, ORIGIN);
        String response = key.get(second.publicKeyJson(), ORIGIN);
        f.now.addAndGet(2_000L);
        expectFailure("transaction_expired", () -> f.service.finish(state, ORIGIN, null, "login", second.transactionId(), response, null));
        expectFailure("preauth_expired", () -> f.service.startLogin(state, ORIGIN));
        assertNotEquals(first.transactionId(), second.transactionId());
    }

    @Test
    public void newLdapLoginInSameBrowserInvalidatesOldTransaction() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        f.ldapLogin(state, "alice", List.of("cn=other"), "none");
        expectFailure("preauth_changed", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));
    }

    @Test
    public void newLdapLoginRightBeforeCommitGetsNoSession() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        f.service.beforeCommitHook = () -> f.ldapLogin(state, "alice", List.of("cn=other"), "none");
        expectFailure("preauth_changed", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));
        assertEquals(0L, f.repository.find("alice").orElseThrow().credentials().get(0).lastUsedAt());
    }

    @Test
    public void logoutRightBeforeCommitGetsNoSession() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        f.service.beforeCommitHook = () -> f.states.clearPreAuth(state, null);
        expectFailure("preauth_changed", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));
    }

    @Test
    public void transactionExpiringWhileWaitingForLockIsRejected() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        f.service.beforeCommitHook = () -> f.now.addAndGet(f.config.getChallengeTtlMillis());
        expectFailure("transaction_expired", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));
    }

    // ------------------------------------------------------------- step-up

    @Test
    public void stepUpAfterPreauthTtlNeedsOnlyWebAuthnAndRotatesToken() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        String oldToken = f.totpSession("alice", List.of("cn=ops"));
        long ldapTime = f.tokens.peekSession(oldToken).orElseThrow().getLdapAuthTime();
        f.now.addAndGet(f.config.getPreauthTtlMillis() * 2);
        f.tokens.getSession(oldToken);

        BrowserState state = f.browser();
        Ceremony ceremony = f.service.startStepUp(state, ORIGIN, oldToken, null);
        key.signCount = 5;
        SessionIssued issued = (SessionIssued) f.service.finish(state, ORIGIN, oldToken, "step_up", ceremony.transactionId(), key.get(ceremony.publicKeyJson(), ORIGIN), null);

        assertFalse(f.tokens.peekSession(oldToken).isPresent());
        Session next = f.tokens.peekSession(issued.token()).orElseThrow();
        assertEquals(AuthenticationMethod.LDAP_WEBAUTHN, next.getMethod());
        assertEquals(ldapTime, next.getLdapAuthTime());
        assertEquals(f.now.get(), next.getWebauthnAuthTime());
        assertEquals(List.of("cn=ops"), next.getGroups());
    }

    @Test
    public void revokedSourceSessionGetsNoNewToken() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        String token = f.totpSession("alice", List.of());
        BrowserState state = f.browser();
        Ceremony ceremony = f.service.startStepUp(state, ORIGIN, token, null);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        f.tokens.invalidateToken(token);
        expectFailure("session_gone", () -> f.service.finish(state, ORIGIN, token, "step_up", ceremony.transactionId(), response, null));
    }

    @Test
    public void sessionRevokedRightBeforeCommitGetsNoNewToken() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        String token = f.totpSession("alice", List.of());
        BrowserState state = f.browser();
        Ceremony ceremony = f.service.startStepUp(state, ORIGIN, token, null);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        f.service.beforeCommitHook = () -> f.tokens.invalidateToken(token);
        expectFailure("session_gone", () -> f.service.finish(state, ORIGIN, token, "step_up", ceremony.transactionId(), response, null));
        assertEquals(0L, f.repository.find("alice").orElseThrow().credentials().get(0).lastUsedAt());
    }

    // ------------------------------------------------------------- logout

    @Test
    public void logoutAfterStepUpPublishedRevokesTheNewToken() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        String oldToken = f.totpSession("alice", List.of());
        BrowserState state = f.browser();
        Ceremony ceremony = f.service.startStepUp(state, ORIGIN, oldToken, null);
        SessionIssued issued = (SessionIssued) f.service.finish(state, ORIGIN, oldToken, "step_up", ceremony.transactionId(),
                key.get(ceremony.publicKeyJson(), ORIGIN), null);
        // the logout request still carries the old cookie: the browser has not applied the new one yet
        f.service.logout(state, oldToken);
        assertFalse(f.tokens.peekSession(issued.token()).isPresent());
    }

    @Test
    public void logoutWithoutCookieRevokesLoginPublishedInThisBrowser() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        String otherDevice = f.login("alice", key);

        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        SessionIssued issued = (SessionIssued) f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(),
                key.get(ceremony.publicKeyJson(), ORIGIN), null);
        f.service.logout(state, null);
        assertFalse(f.tokens.peekSession(issued.token()).isPresent());
        // other browsers of the same user keep their sessions
        assertTrue(f.tokens.peekSession(otherDevice).isPresent());
    }

    @Test
    public void logoutRacingAPassedLoginCommitRevokesItsSession() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);

        java.util.concurrent.CountDownLatch checked = new java.util.concurrent.CountDownLatch(1);
        // the commit has passed its re-checks and holds the browser state monitor; logout starts now
        f.service.afterCheckHook = () -> {
            checked.countDown();
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
        Thread logout = new Thread(() -> {
            try {
                checked.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            f.service.logout(state, null);
        });
        logout.start();
        SessionIssued issued = (SessionIssued) f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null);
        logout.join();
        assertFalse(f.tokens.peekSession(issued.token()).isPresent());
        assertNull(state.preAuth());
    }

    @Test
    public void preAuthFromOldPasswordCannotFinishAfterPasswordChange() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        f.now.addAndGet(1_000L);
        f.service.revokeAfterPasswordChange("alice", "alice");
        expectFailure("unknown_transaction", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));
        assertNull(state.preAuth());

        // a request that read the generation before its bind cannot publish once the password changed,
        // even if its directory read finished after the change
        long before = f.service.loginGeneration("alice");
        f.service.revokeAfterPasswordChange(null, "ALICE");
        BrowserState racing = f.browser();
        com.payneteasy.nginxauth.ldap.LdapPrincipal principal =
                new com.payneteasy.nginxauth.ldap.LdapPrincipal("alice", "alice", List.of(), f.now.get() + 10_000L, "alice");
        assertFalse(f.service.beginPreAuth(racing, racing.generation(), PreAuth.create(principal, "none", "/", before)));
        Session session = Session.withoutWebAuthn("alice", "alice", List.of(), AuthenticationMethod.LDAP_TOTP, f.now.get() + 10_000L);
        assertFalse(f.service.issueSession(racing, racing.generation(), session.withLogin("alice", before)).isPresent());
        assertTrue(f.service.issueSession(racing, racing.generation(),
                session.withLogin("alice", f.service.loginGeneration("alice"), f.service.nextLoginSequence())).isPresent());
    }

    @Test
    public void passwordChangeWithUnknownUidStopsPendingLogin() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        f.service.revokeAfterPasswordChange(null, "Alice");
        try {
            f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null);
            fail("login started with the old password must not finish");
        } catch (WebAuthnException e) {
            assertTrue(e.reason(), e.reason().equals("preauth_changed") || e.reason().equals("password_changed"));
        }
    }

    @Test
    public void recoveryKeyIsNotSavedAfterPasswordChange() throws Exception {
        f = new WebAuthnFixture();
        String secret = f.service.adminIssueGrant("alice", new WebAuthnService.GrantSpec(24, 1, "test"));
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        assertTrue(f.service.verifyRecoverySecret(state, secret));
        Ceremony create = f.service.startRecoveryEnroll(state, ORIGIN);
        String response = new SoftAuthenticator().create(create.publicKeyJson(), ORIGIN);
        // the password changes after the commit re-checks passed
        f.service.afterCheckHook = () -> f.service.revokeAfterPasswordChange(null, "alice");
        try {
            f.service.finish(state, ORIGIN, null, "recovery_enroll", create.transactionId(), response, null);
            fail("key must not be saved after the password change");
        } catch (WebAuthnException e) {
            assertTrue(e.reason(), e.reason().equals("password_changed") || e.reason().equals("preauth_changed"));
        }
        UserRecord record = f.repository.find("alice").orElseThrow();
        assertTrue(record.credentials().isEmpty());
        assertEquals(1, record.enrollmentGrant().usesLeft());
    }

    @Test
    public void sessionOperationsStopOnceThePasswordChanged() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.browser();
        String token = f.tokens.createSession(Session.withoutWebAuthn("alice", "alice", List.of(), AuthenticationMethod.LDAP_TOTP, f.now.get())
                .withLogin("alice", f.service.loginGeneration("alice")));
        Ceremony ceremony = f.service.startDelete(state, ORIGIN, token, key.credentialId(), true);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        f.service.afterCheckHook = () -> f.service.revokeAfterPasswordChange(null, "alice");
        try {
            f.service.finish(state, ORIGIN, token, "delete_credential", ceremony.transactionId(), response, null);
            fail("deletion must not be committed after the password change");
        } catch (WebAuthnException e) {
            assertTrue(e.reason(), e.reason().equals("password_changed") || e.reason().equals("session_gone"));
        }
        assertEquals(1, f.repository.find("alice").orElseThrow().credentials().size());

        Session stale = Session.withoutWebAuthn("bob", "bob", List.of(), AuthenticationMethod.LDAP_TOTP, f.now.get()).withLogin("bob", 0L);
        assertTrue(f.service.isCurrent(stale));
        f.service.revokeAfterPasswordChange(null, "BOB");
        assertFalse(f.service.isCurrent(stale));
    }

    @Test
    public void passwordChangeRevokesOtherSpellingsOfTheLogin() throws Exception {
        f = new WebAuthnFixture();
        String other = f.tokens.createSession(Session.withoutWebAuthn("osmith", "Olga", List.of(), AuthenticationMethod.LDAP_TOTP, f.now.get())
                .withLogin("Olga  Smith", 0L));
        f.service.revokeAfterPasswordChange(null, "olga smith");
        assertFalse(f.tokens.peekSession(other).isPresent());
    }

    @Test
    public void invisibleCharactersDoNotEscapeRevocation() throws Exception {
        f = new WebAuthnFixture();
        Session alice = Session.withoutWebAuthn("alice", "Alice", List.of(), AuthenticationMethod.LDAP_TOTP, f.now.get()).withLogin("Alice", 0L);
        String token = f.tokens.createSession(alice);
        f.service.revokeAfterPasswordChange(null, "Al\u00ADice");
        assertFalse(f.tokens.peekSession(token).isPresent());
        assertFalse(f.service.isCurrent(alice));
    }

    @Test
    public void uidCleanupEndsEverySpellingAndLetsTheChangerContinue() throws Exception {
        f = new WebAuthnFixture();
        long before = f.service.nextLoginSequence();
        String stolen = f.tokens.createSession(Session.withoutWebAuthn("osmith", "Olga", List.of(), AuthenticationMethod.LDAP_TOTP, f.now.get())
                .withLogin("osmith", 0L, before));
        long generation = f.service.revokeAfterPasswordChange(null, "Olga Smith");
        assertTrue(f.tokens.peekSession(stolen).isPresent());
        f.service.revokeUserAfterPasswordChange("osmith");
        assertFalse(f.tokens.peekSession(stolen).isPresent());
        // the changing request takes a new number after the revocation and may publish
        Session own = Session.withoutWebAuthn("osmith", "Olga", List.of(), AuthenticationMethod.LDAP_TOTP, f.now.get())
                .withLogin("Olga Smith", generation, f.service.nextLoginSequence());
        BrowserState state = f.browser();
        assertTrue(f.service.issueSession(state, state.generation(), own).isPresent());
    }

    @Test
    public void exoticSpellingStartedBeforeChangeCannotPublish() throws Exception {
        f = new WebAuthnFixture();
        // login as "ℂlice" read its sequence and generation before the bind
        long sequence = f.service.nextLoginSequence();
        long generation = f.service.loginGeneration("\u2102lice");
        // password change of the same entry typed as "Clice", uid known
        f.service.revokeAfterPasswordChange("clice", "Clice");
        Session late = Session.withoutWebAuthn("clice", "Clice", List.of(), AuthenticationMethod.LDAP_TOTP, f.now.get())
                .withLogin("\u2102lice", generation, sequence);
        BrowserState state = f.browser();
        assertFalse(f.service.issueSession(state, state.generation(), late).isPresent());
        assertFalse(f.service.isCurrent(late));
        PreAuth pre = PreAuth.create(new com.payneteasy.nginxauth.ldap.LdapPrincipal("clice", "Clice", List.of(), f.now.get(), "\u2102lice"),
                "none", "/", generation, sequence);
        assertFalse(f.service.beginPreAuth(state, state.generation(), pre));
    }

    @Test
    public void passwordChangeRevokesSessionPublishedJustBefore() throws Exception {
        f = new WebAuthnFixture();
        BrowserState state = f.browser();
        long before = f.service.loginGeneration("bob");
        Session session = Session.withoutWebAuthn("bob", "bob", List.of(), AuthenticationMethod.LDAP_TOTP, f.now.get()).withLogin("Bob", before);
        String token = f.service.issueSession(state, state.generation(), session).orElseThrow();
        f.service.revokeAfterPasswordChange(null, "bob");
        assertFalse(f.tokens.peekSession(token).isPresent());
    }

    @Test
    public void requestStartedBeforeLogoutPublishesNothing() throws Exception {
        f = new WebAuthnFixture();
        BrowserState state = f.browser();
        long generation = state.generation();
        f.service.logout(state, null);
        Session session = Session.withoutWebAuthn("alice", "alice", List.of(), AuthenticationMethod.LDAP_TOTP, f.now.get());
        assertFalse(f.service.issueSession(state, generation, session).isPresent());
        PreAuth pre = PreAuth.create(new com.payneteasy.nginxauth.ldap.LdapPrincipal("alice", "alice", List.of(), f.now.get()), "none", "/", 0L);
        assertFalse(f.service.beginPreAuth(state, generation, pre));
        assertNull(state.preAuth());
        assertTrue(f.service.issueSession(state, state.generation(), session).isPresent());
    }

    // ------------------------------------------------------------- bootstrap race

    @Test
    public void secondBootstrapDoesNotCompleteAfterFirst() throws Exception {
        f = new WebAuthnFixture();
        String token = f.totpSession("alice", List.of());
        BrowserState browser1 = f.browser();
        BrowserState browser2 = f.browser();
        Ceremony c1 = f.service.startRegister(browser1, ORIGIN, token);
        Ceremony c2 = f.service.startRegister(browser2, ORIGIN, token);
        assertEquals("create", c1.type());
        assertEquals("create", c2.type());

        f.service.finish(browser1, ORIGIN, token, "register", c1.transactionId(), new SoftAuthenticator().create(c1.publicKeyJson(), ORIGIN), "one");
        String second = new SoftAuthenticator().create(c2.publicKeyJson(), ORIGIN);
        expectFailure("bootstrap_lost", () -> f.service.finish(browser2, ORIGIN, token, "register", c2.transactionId(), second, "two"));
        assertEquals(1, f.repository.find("alice").orElseThrow().credentials().size());
    }

    @Test
    public void logoutBeforeRegistrationCommitStoresNothing() throws Exception {
        f = new WebAuthnFixture();
        String token = f.totpSession("alice", List.of());
        BrowserState state = f.browser();
        Ceremony ceremony = f.service.startRegister(state, ORIGIN, token);
        String response = new SoftAuthenticator().create(ceremony.publicKeyJson(), ORIGIN);
        f.service.beforeCommitHook = () -> f.tokens.invalidateToken(token);
        expectFailure("session_gone", () -> f.service.finish(state, ORIGIN, token, "register", ceremony.transactionId(), response, null));
        assertTrue(f.repository.find("alice").orElseThrow().credentials().isEmpty());
    }

    // ------------------------------------------------------------- flags and counter

    @Test
    public void backupEligibilityMustNotChange() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        key.backupEligible = true;
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        try {
            f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null);
            fail("BE change must be rejected");
        } catch (WebAuthnException e) {
            assertTrue(e.reason(), e.reason().equals("assertion_invalid") || e.reason().equals("be_mismatch"));
        }
    }

    @Test
    public void notBackupEligibleButBackedUpIsRejectedAtRegistration() throws Exception {
        f = new WebAuthnFixture();
        String token = f.totpSession("alice", List.of());
        BrowserState state = f.browser();
        Ceremony ceremony = f.service.startRegister(state, ORIGIN, token);
        SoftAuthenticator key = new SoftAuthenticator();
        key.backupState = true;
        String response = key.create(ceremony.publicKeyJson(), ORIGIN);
        try {
            f.service.finish(state, ORIGIN, token, "register", ceremony.transactionId(), response, null);
            fail("BE=0,BS=1 must be rejected");
        } catch (WebAuthnException e) {
            assertTrue(e.reason(), e.reason().equals("registration_invalid") || e.reason().equals("flags_invalid") || e.reason().equals("malformed_response"));
        }
        assertTrue(f.repository.find("alice").orElseThrow().credentials().isEmpty());
    }

    @Test
    public void backupStateIsUpdatedOnlyAfterSuccess() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        key.backupEligible = true;
        f.bootstrap("alice", key);
        assertFalse(f.repository.find("alice").orElseThrow().credentials().get(0).backupState());

        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        key.backupState = true;
        key.userVerified = false;
        String bad = key.get(ceremony.publicKeyJson(), ORIGIN);
        expectFailure("assertion_invalid", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), bad, null));
        assertFalse(f.repository.find("alice").orElseThrow().credentials().get(0).backupState());

        key.userVerified = true;
        f.login("alice", key);
        assertTrue(f.repository.find("alice").orElseThrow().credentials().get(0).backupState());
    }

    @Test
    public void signCountAnomalyIsRejectedUnderLock() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);

        // two ceremonies started in parallel, both answered with the same counter
        BrowserState b1 = f.ldapLogin("alice", List.of(), "none");
        BrowserState b2 = f.ldapLogin("alice", List.of(), "none");
        Ceremony c1 = f.service.startLogin(b1, ORIGIN);
        Ceremony c2 = f.service.startLogin(b2, ORIGIN);
        key.signCount = 7;
        String r1 = key.get(c1.publicKeyJson(), ORIGIN);
        String r2 = key.get(c2.publicKeyJson(), ORIGIN);
        assertTrue(f.service.finish(b1, ORIGIN, null, "login", c1.transactionId(), r1, null) instanceof SessionIssued);
        expectFailure("signcount_anomaly", () -> f.service.finish(b2, ORIGIN, null, "login", c2.transactionId(), r2, null));
        assertEquals(7, f.repository.find("alice").orElseThrow().credentials().get(0).signCount());
    }

    @Test
    public void zeroCounterStaysAcceptable() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        f.login("alice", key);
        f.login("alice", key);
        assertEquals(0, f.repository.find("alice").orElseThrow().credentials().get(0).signCount());
    }

    @Test
    public void warnPolicyAcceptsAnomalyButNeverDecreases() throws Exception {
        f = new WebAuthnFixture(PolicySet.EMPTY, WebAuthnConfig.CounterPolicy.WARN);
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        key.signCount = 10;
        f.login("alice", key);
        key.signCount = 3;
        f.login("alice", key);
        assertEquals(10, f.repository.find("alice").orElseThrow().credentials().get(0).signCount());
    }

    // ------------------------------------------------------------- policy

    @Test
    public void singleDevicePolicyRejectsMultiDeviceRegistrationAndLogin() throws Exception {
        PolicySet policies = PolicySet.parse("{\"version\":1,\"groups\":{\"ops\":{\"requireSingleDeviceCredential\":true}}}");
        f = new WebAuthnFixture(policies, WebAuthnConfig.CounterPolicy.REJECT);

        // registered before joining the group
        SoftAuthenticator synced = new SoftAuthenticator();
        synced.backupEligible = true;
        f.bootstrap("alice", synced);

        BrowserState state = f.ldapLogin("alice", List.of("cn=ops,ou=groups,dc=example,dc=com"), "none");
        expectFailure("no_eligible_credentials", () -> f.service.startLogin(state, ORIGIN));
    }

    @Test
    public void bootstrapIsForbiddenWhenWebAuthnIsRequired() throws Exception {
        PolicySet policies = PolicySet.parse("{\"version\":1,\"groups\":{\"admins\":{\"requireWebAuthn\":true}}}");
        f = new WebAuthnFixture(policies, WebAuthnConfig.CounterPolicy.REJECT);
        String token = f.totpSession("alice", List.of("cn=admins,dc=example,dc=com"));
        expectFailure("bootstrap_forbidden", () -> f.service.startRegister(f.browser(), ORIGIN, token));
    }

    // ------------------------------------------------------------- delete

    @Test
    public void deletingCredentialEndsItsSessions() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator first = new SoftAuthenticator();
        f.bootstrap("alice", first);
        first.signCount = 1;
        String firstSession = f.login("alice", first);

        BrowserState state = f.browser();
        String manager = f.totpSession("alice", List.of());
        expectFailure("confirm_last_required", () -> f.service.startDelete(state, ORIGIN, manager, first.credentialId(), false));

        Ceremony confirmed = f.service.startDelete(state, ORIGIN, manager, first.credentialId(), true);
        first.signCount = 3;
        assertTrue(f.service.finish(state, ORIGIN, manager, "delete_credential", confirmed.transactionId(), first.get(confirmed.publicKeyJson(), ORIGIN), null) instanceof Done);
        assertTrue(f.repository.find("alice").orElseThrow().credentials().isEmpty());
        assertFalse(f.tokens.peekSession(firstSession).isPresent());
        assertTrue(f.tokens.peekSession(manager).isPresent());
    }

    @Test
    public void lastCredentialOfRequiredUserCannotBeDeleted() throws Exception {
        PolicySet policies = PolicySet.parse("{\"version\":1,\"groups\":{\"admins\":{\"requireWebAuthn\":true}}}");
        f = new WebAuthnFixture(policies, WebAuthnConfig.CounterPolicy.REJECT);
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        String token = f.totpSession("alice", List.of("cn=admins"));
        expectFailure("last_credential_required", () -> f.service.startDelete(f.browser(), ORIGIN, token, key.credentialId(), true));
    }

    // ------------------------------------------------------------- recovery and reset

    @Test
    public void recoveryNeedsSecretAndConsumesGrantOnSave() throws Exception {
        PolicySet policies = PolicySet.parse("{\"version\":1,\"groups\":{\"admins\":{\"requireWebAuthn\":true}}}");
        f = new WebAuthnFixture(policies, WebAuthnConfig.CounterPolicy.REJECT);
        String secret = f.service.adminIssueGrant("alice", new WebAuthnService.GrantSpec(24, 1, "test"));

        BrowserState state = f.ldapLogin("alice", List.of("cn=admins"), "none");
        expectFailure("no_recovery_permit", () -> f.service.startRecoveryEnroll(state, ORIGIN));

        assertTrue(f.service.verifyRecoverySecret(state, secret.toLowerCase().replace("-", " ")));
        Ceremony create = f.service.startRecoveryEnroll(state, ORIGIN);
        SoftAuthenticator key = new SoftAuthenticator();
        NextCeremony next = (NextCeremony) f.service.finish(state, ORIGIN, null, "recovery_enroll", create.transactionId(), key.create(create.publicKeyJson(), ORIGIN), "new");
        assertNull(f.repository.find("alice").orElseThrow().enrollmentGrant());

        Ceremony login = next.ceremony();
        SessionIssued issued = (SessionIssued) f.service.finish(state, ORIGIN, null, "login", login.transactionId(), key.get(login.publicKeyJson(), ORIGIN), null);
        assertEquals(AuthenticationMethod.LDAP_WEBAUTHN, f.tokens.peekSession(issued.token()).orElseThrow().getMethod());
    }

    @Test
    public void wrongSecretEndsPreauth() throws Exception {
        f = new WebAuthnFixture();
        f.service.adminIssueGrant("alice", new WebAuthnService.GrantSpec(24, 1, "test"));
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        assertFalse(f.service.verifyRecoverySecret(state, "AAAA-BBBB"));
        assertNull(state.preAuth());
    }

    @Test
    public void expiredGrantIsRejected() throws Exception {
        f = new WebAuthnFixture();
        String secret = f.service.adminIssueGrant("alice", new WebAuthnService.GrantSpec(1, 1, "test"));
        f.now.addAndGet(3_600_001L);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        assertFalse(f.service.verifyRecoverySecret(state, secret));
    }

    @Test
    public void twoRecoveryFinishesWithOneUseSaveOneCredential() throws Exception {
        f = new WebAuthnFixture();
        String secret = f.service.adminIssueGrant("alice", new WebAuthnService.GrantSpec(24, 1, "test"));
        BrowserState b1 = f.ldapLogin("alice", List.of(), "none");
        BrowserState b2 = f.ldapLogin("alice", List.of(), "none");
        assertTrue(f.service.verifyRecoverySecret(b1, secret));
        assertTrue(f.service.verifyRecoverySecret(b2, secret));
        Ceremony c1 = f.service.startRecoveryEnroll(b1, ORIGIN);
        Ceremony c2 = f.service.startRecoveryEnroll(b2, ORIGIN);
        f.service.finish(b1, ORIGIN, null, "recovery_enroll", c1.transactionId(), new SoftAuthenticator().create(c1.publicKeyJson(), ORIGIN), null);
        String second = new SoftAuthenticator().create(c2.publicKeyJson(), ORIGIN);
        expectFailure("grant_invalid", () -> f.service.finish(b2, ORIGIN, null, "recovery_enroll", c2.transactionId(), second, null));
        assertEquals(1, f.repository.find("alice").orElseThrow().credentials().size());
    }

    @Test
    public void grantExpiringWhileWaitingForLockIsNotUsed() throws Exception {
        f = new WebAuthnFixture();
        String secret = f.service.adminIssueGrant("alice", new WebAuthnService.GrantSpec(1, 1, "test"));
        f.now.addAndGet(3_600_000L - 10_000L);
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        assertTrue(f.service.verifyRecoverySecret(state, secret));
        Ceremony create = f.service.startRecoveryEnroll(state, ORIGIN);
        String response = new SoftAuthenticator().create(create.publicKeyJson(), ORIGIN);
        f.service.beforeCommitHook = () -> f.now.addAndGet(20_000L);
        expectFailure("grant_invalid", () -> f.service.finish(state, ORIGIN, null, "recovery_enroll", create.transactionId(), response, null));
        UserRecord record = f.repository.find("alice").orElseThrow();
        assertTrue(record.credentials().isEmpty());
        assertEquals(1, record.enrollmentGrant().usesLeft());
    }

    @Test
    public void unknownTransportsAreNotStored() throws Exception {
        f = new WebAuthnFixture();
        String token = f.totpSession("alice", List.of());
        BrowserState state = f.browser();
        Ceremony ceremony = f.service.startRegister(state, ORIGIN, token);
        String response = new SoftAuthenticator().create(ceremony.publicKeyJson(), ORIGIN)
                .replace("\"transports\":[\"usb\"]", "\"transports\":[\"usb\",\"" + "x".repeat(50_000) + "\"]");
        f.service.finish(state, ORIGIN, token, "register", ceremony.transactionId(), response, null);
        assertEquals(List.of("usb"), f.repository.find("alice").orElseThrow().credentials().get(0).transports());
    }

    @Test
    public void resetDuringLoginBlocksOldTransaction() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        String handle = f.repository.find("alice").orElseThrow().userHandle();
        String session = f.login("alice", key);

        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        String response = key.get(ceremony.publicKeyJson(), ORIGIN);
        f.service.beforeCommitHook = () -> {
            try {
                f.service.adminReset("alice", null);
            } catch (WebAuthnException e) {
                throw new IllegalStateException(e);
            }
        };
        expectFailure("reset", () -> f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), response, null));

        UserRecord record = f.repository.find("alice").orElseThrow();
        assertTrue(record.credentials().isEmpty());
        assertEquals(handle, record.userHandle());
        assertFalse(f.tokens.peekSession(session).isPresent());
    }

    @Test
    public void resetRevokesOldGrantAndCanIssueNew() throws Exception {
        f = new WebAuthnFixture();
        String oldSecret = f.service.adminIssueGrant("alice", new WebAuthnService.GrantSpec(24, 1, "test"));
        Optional<String> newSecret = f.service.adminReset("alice", new WebAuthnService.GrantSpec(24, 1, "test"));
        assertTrue(newSecret.isPresent());
        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        assertFalse(f.service.verifyRecoverySecret(state, oldSecret));
        BrowserState state2 = f.ldapLogin("alice", List.of(), "none");
        assertTrue(f.service.verifyRecoverySecret(state2, newSecret.get()));
    }

    @Test
    public void sameCredentialIdForTwoUsersIsRejected() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator alice = new SoftAuthenticator();
        SoftAuthenticator bob = new SoftAuthenticator().copyWithSameCredentialId(alice);
        f.bootstrap("alice", alice);
        String token = f.totpSession("bob", List.of());
        BrowserState state = f.browser();
        Ceremony ceremony = f.service.startRegister(state, ORIGIN, token);
        String response = bob.create(ceremony.publicKeyJson(), ORIGIN);
        try {
            f.service.finish(state, ORIGIN, token, "register", ceremony.transactionId(), response, null);
            fail("duplicate credential ID must be rejected");
        } catch (WebAuthnException e) {
            // the library rejects a known ID; the repository index guards the concurrent case
            assertTrue(e.reason(), e.reason().equals("registration_invalid") || e.reason().equals("duplicate_credential"));
        }
        assertTrue(f.repository.find("bob").orElseThrow().credentials().isEmpty());
        assertEquals(Optional.of("alice"), f.repository.ownerOfCredential(alice.credentialId()));
    }

    @Test
    public void storedCredentialHasMetadata() throws Exception {
        f = new WebAuthnFixture();
        SoftAuthenticator key = new SoftAuthenticator(UUID.fromString("cb69481e-8ff7-4039-93ec-0a2729a154a8"));
        f.bootstrap("alice", key);
        StoredCredential stored = f.repository.find("alice").orElseThrow().credentials().get(0);
        assertEquals("cb69481e-8ff7-4039-93ec-0a2729a154a8", stored.aaguid());
        assertEquals(List.of("usb"), stored.transports());
        assertEquals("key", stored.name());
        assertEquals(f.now.get(), stored.createdAt());
    }
}
