package com.payneteasy.nginxauth.webauthn;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import com.google.gson.JsonParser;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.Ceremony;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.SessionIssued;
import org.junit.After;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static com.payneteasy.nginxauth.webauthn.WebAuthnFixture.ORIGIN;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Runs successful and failing ceremonies with all loggers at DEBUG and checks that no log line carries
 * credential IDs, challenges, assertions, tokens or enrollment secrets.
 */
public class LogLeakTest {

    private WebAuthnFixture f;
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private Logger root;
    private Level previous;

    @After
    public void tearDown() throws Exception {
        if (root != null) {
            root.detachAppender(appender);
            root.setLevel(previous);
        }
        if (f != null) {
            f.deleteAll();
        }
    }

    @Test
    public void noSecretsInLogs() throws Exception {
        root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        previous = root.getLevel();
        root.setLevel(Level.DEBUG);
        appender.start();
        root.addAppender(appender);

        f = new WebAuthnFixture();
        List<String> secrets = new ArrayList<>();

        SoftAuthenticator key = new SoftAuthenticator();
        f.bootstrap("alice", key);
        secrets.add(key.credentialId());

        BrowserState state = f.ldapLogin("alice", List.of(), "none");
        Ceremony ceremony = f.service.startLogin(state, ORIGIN);
        secrets.add(challenge(ceremony));
        key.userVerified = false;
        String bad = key.get(ceremony.publicKeyJson(), ORIGIN);
        secrets.add(signature(bad));
        try {
            f.service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), bad, null);
        } catch (WebAuthnException expected) {
            // ok
        }
        key.userVerified = true;
        Ceremony retry = f.service.startLogin(state, ORIGIN);
        String good = key.get(retry.publicKeyJson(), ORIGIN);
        SessionIssued issued = (SessionIssued) f.service.finish(state, ORIGIN, null, "login", retry.transactionId(), good, null);
        secrets.add(issued.token());
        secrets.add(retry.transactionId());

        String secret = f.service.adminIssueGrant("bob", new WebAuthnService.GrantSpec(24, 1, "it"));
        secrets.add(secret);
        secrets.add(EnrollmentSecrets.normalize(secret));
        BrowserState bob = f.ldapLogin("bob", List.of(), "none");
        f.service.verifyRecoverySecret(bob, "WRONG-SECRET");

        assertFalse(appender.list.isEmpty());
        boolean audited = false;
        for (ILoggingEvent event : appender.list) {
            String text = render(event);
            audited |= event.getLoggerName().equals("nginx-auth.audit");
            for (String value : secrets) {
                assertFalse("log leaks a secret: " + text, text.contains(value));
            }
        }
        assertTrue(audited);
    }

    private static String challenge(Ceremony aCeremony) {
        return JsonParser.parseString(aCeremony.publicKeyJson()).getAsJsonObject()
                .getAsJsonObject("publicKey").get("challenge").getAsString();
    }

    private static String signature(String aCredential) {
        return JsonParser.parseString(aCredential).getAsJsonObject().getAsJsonObject("response").get("signature").getAsString();
    }

    private static String render(ILoggingEvent aEvent) {
        StringBuilder sb = new StringBuilder(aEvent.getFormattedMessage());
        IThrowableProxy proxy = aEvent.getThrowableProxy();
        while (proxy != null) {
            sb.append(' ').append(proxy.getClassName()).append(": ").append(proxy.getMessage());
            proxy = proxy.getCause();
        }
        return sb.toString();
    }
}
