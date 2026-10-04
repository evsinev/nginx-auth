package com.payneteasy.nginxauth.integration;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.payneteasy.nginxauth.policy.PolicySet;
import org.junit.After;
import org.junit.Test;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * {@code X-Auth-User} / {@code X-Auth-Groups} in the response of {@code /auth/nginx-auth-request-check}.
 */
public class IdentityHeadersHttpTest {

    private static final Pattern NONCE = Pattern.compile("name=\"j_nonce\" value=\"([^\"]+)\"");

    private TestServer server;
    private Logger logger;
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @After
    public void tearDown() throws Exception {
        System.clearProperty("AUTH_REQUEST_USER_HEADER");
        System.clearProperty("AUTH_REQUEST_GROUPS_HEADER");
        if (logger != null) {
            logger.detachAppender(appender);
        }
        if (server != null) {
            server.close();
        }
    }

    private Browser webAuthnLogin(String aUser) throws Exception {
        server.totpUsers.put(aUser, true);
        Browser browser = new Browser(server.port);
        Browser.Response page = browser.get("/auth?back=%2Fapp");
        assertEquals(200, page.status);
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("j_username", aUser);
        fields.put("j_password", "pw");
        fields.put("j_code", TestServer.TOTP_CODE);
        fields.put("j_csrf", page.csrf());
        fields.put("back", "/app");
        assertEquals(302, browser.postForm("/auth/login", fields).status);
        return browser;
    }

    private Browser legacyLogin(String aUser) throws Exception {
        Browser browser = new Browser(server.port);
        Matcher nonce = NONCE.matcher(browser.get("/auth?back=%2Fapp").body);
        assertTrue(nonce.find());
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("j_username", aUser);
        fields.put("j_password", "pw");
        fields.put("j_nonce", nonce.group(1));
        fields.put("back", "/app");
        assertEquals(302, browser.postForm("/auth/login", fields, null).status);
        return browser;
    }

    private static Browser.Response check(Browser aBrowser, String aPolicyId, String... aExtraHeaders) throws Exception {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Original-URI", "/app");
        headers.put("X-Policy-Id", aPolicyId);
        for (int i = 0; i < aExtraHeaders.length; i += 2) {
            headers.put(aExtraHeaders[i], aExtraHeaders[i + 1]);
        }
        return aBrowser.get("/auth/nginx-auth-request-check", headers);
    }

    private void captureLog() {
        logger = (Logger) LoggerFactory.getLogger("com.payneteasy.nginxauth.servlet.IdentityHeaders");
        appender.start();
        logger.addAppender(appender);
    }

    @Test
    public void uidAndShortGroupNamesOnAllow() throws Exception {
        server = new TestServer(true, PolicySet.EMPTY, true);
        server.user("Alice.Login", "pw",
                "cn=wk-admins,ou=groups,dc=example,dc=com",
                "CN=wk-ops,ou=groups,dc=example,dc=com",
                "cn=wk-admins,ou=other,dc=example,dc=com",
                "plain-group");
        server.uids.put("Alice.Login", "alice");
        Browser browser = webAuthnLogin("Alice.Login");

        Browser.Response allowed = check(browser, "none");
        assertEquals(200, allowed.status);
        assertEquals("alice", allowed.header("X-Auth-User"));
        assertEquals("wk-admins,wk-ops,plain-group", allowed.header("X-Auth-Groups"));
    }

    @Test
    public void noIdentityOnLoginOrForbidden() throws Exception {
        server = new TestServer(true, PolicySet.parse("{\"version\":1,\"locations\":{\"wk\":{\"requireWebAuthn\":false}}}"), true);
        server.user("alice", "pw", "cn=wk-admins,ou=groups,dc=example,dc=com");
        Browser browser = webAuthnLogin("alice");
        assertEquals("alice", check(browser, "wk").header("X-Auth-User"));

        Browser.Response anonymous = check(new Browser(server.port), "wk");
        assertEquals(401, anonymous.status);
        assertNull(anonymous.header("X-Auth-User"));
        assertNull(anonymous.header("X-Auth-Groups"));

        Browser.Response forbidden = check(browser, "no-such-policy");
        assertEquals(403, forbidden.status);
        assertNull(forbidden.header("X-Auth-User"));
        assertNull(forbidden.header("X-Auth-Groups"));

        server.app.tokens().invalidateToken(browser.cookies.get("AUTH_TOKEN"));
        Browser.Response revoked = check(browser, "wk");
        assertEquals(401, revoked.status);
        assertNull(revoked.header("X-Auth-User"));
        assertNull(revoked.header("X-Auth-Groups"));
    }

    @Test
    public void unsafeUidIsNotSentAndNotLoggedRaw() throws Exception {
        captureLog();
        server = new TestServer(true, PolicySet.EMPTY, true);
        server.user("bob", "pw", "cn=wk-ops,ou=groups,dc=example,dc=com");
        server.uids.put("bob", "bob\r\nX-Auth-Groups: wk-admins");
        Browser browser = webAuthnLogin("bob");

        Browser.Response allowed = check(browser, "none");
        assertEquals(200, allowed.status);
        assertNull(allowed.header("X-Auth-User"));
        assertEquals("wk-ops", allowed.header("X-Auth-Groups"));
        assertTrue(appender.list.stream().anyMatch(e -> e.getFormattedMessage().contains("cannot be sent in X-Auth-User")));
        assertFalse(appender.list.stream().anyMatch(e -> e.getFormattedMessage().contains("\r") || e.getFormattedMessage().contains("\n")));
    }

    @Test
    public void unsafeGroupsAreSkipped() throws Exception {
        captureLog();
        server = new TestServer(true, PolicySet.EMPTY, true);
        server.user("alice", "pw",
                "cn=a\\,b,ou=groups,dc=example,dc=com",
                "cn=админы,ou=groups,dc=example,dc=com",
                "ou=not-cn,dc=example,dc=com",
                "cn=bad\\0d\\0aname,ou=groups,dc=example,dc=com",
                "cn=wk-dcv,ou=groups,dc=example,dc=com");
        Browser browser = webAuthnLogin("alice");

        Browser.Response allowed = check(browser, "none");
        assertEquals(200, allowed.status);
        assertEquals("alice", allowed.header("X-Auth-User"));
        assertEquals("wk-dcv", allowed.header("X-Auth-Groups"));
        assertEquals(4, appender.list.stream().filter(e -> e.getFormattedMessage().contains("cannot be sent in X-Auth-Groups")).count());
    }

    @Test
    public void emptySettingTurnsHeaderOff() throws Exception {
        System.setProperty("AUTH_REQUEST_USER_HEADER", "");
        server = new TestServer(true, PolicySet.EMPTY, true);
        server.user("alice", "pw", "cn=wk-admins,ou=groups,dc=example,dc=com");
        Browser browser = webAuthnLogin("alice");

        Browser.Response allowed = check(browser, "none");
        assertEquals(200, allowed.status);
        assertNull(allowed.header("X-Auth-User"));
        assertEquals("wk-admins", allowed.header("X-Auth-Groups"));
    }

    @Test
    public void headerNamesAreConfigurable() throws Exception {
        System.setProperty("AUTH_REQUEST_USER_HEADER", "X-Remote-User");
        System.setProperty("AUTH_REQUEST_GROUPS_HEADER", "X-Remote-Groups");
        server = new TestServer(true, PolicySet.EMPTY, true);
        server.user("alice", "pw", "cn=wk-admins,ou=groups,dc=example,dc=com");
        Browser browser = webAuthnLogin("alice");

        Browser.Response allowed = check(browser, "none");
        assertEquals("alice", allowed.header("X-Remote-User"));
        assertEquals("wk-admins", allowed.header("X-Remote-Groups"));
        assertNull(allowed.header("X-Auth-User"));
    }

    @Test
    public void clientHeadersAreNotReflected() throws Exception {
        server = new TestServer(true, PolicySet.EMPTY, true);
        server.user("alice", "pw");
        Browser browser = webAuthnLogin("alice");

        Browser.Response allowed = check(browser, "none", "X-Auth-User", "root", "X-Auth-Groups", "wk-admins");
        assertEquals(200, allowed.status);
        assertEquals("alice", allowed.header("X-Auth-User"));
        assertNull(allowed.header("X-Auth-Groups"));

        Browser.Response anonymous = check(new Browser(server.port), "none", "X-Auth-User", "root");
        assertEquals(401, anonymous.status);
        assertNull(anonymous.header("X-Auth-User"));
    }

    @Test
    public void legacyModeSendsTypedNameWithoutGroups() throws Exception {
        captureLog();
        server = new TestServer(false, PolicySet.EMPTY, false);
        server.user("alice", "pw", "cn=wk-admins,ou=groups,dc=example,dc=com");
        server.user("alice smith", "pw");

        Browser.Response allowed = check(legacyLogin("alice"), "anything");
        assertEquals(200, allowed.status);
        assertEquals("alice", allowed.header("X-Auth-User"));
        assertNull(allowed.header("X-Auth-Groups"));

        Browser.Response spaced = check(legacyLogin("alice smith"), "anything");
        assertEquals(200, spaced.status);
        assertNull(spaced.header("X-Auth-User"));
        assertTrue(appender.list.stream().anyMatch(e -> e.getFormattedMessage().contains("alice_smith")));
    }
}
