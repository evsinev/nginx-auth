package com.payneteasy.nginxauth.integration;

import com.payneteasy.nginxauth.policy.PolicySet;
import org.junit.After;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * WEBAUTHN_ENABLED=false: the original nonce-based flow, no binding cookie, no login context.
 */
public class LegacyModeHttpTest {

    private static final Pattern NONCE = Pattern.compile("name=\"j_nonce\" value=\"([^\"]+)\"");

    private TestServer server;

    @After
    public void tearDown() throws Exception {
        if (server != null) {
            server.close();
        }
    }

    @Test
    public void totpLoginAndAuthRequest() throws Exception {
        server = new TestServer(false, PolicySet.EMPTY, true);
        server.user("alice", "pw");
        server.totpUsers.put("alice", true);
        Browser browser = new Browser(server.port);

        Browser.Response page = browser.get("/auth?back=%2Fapp");
        assertEquals(200, page.status);
        assertNull(browser.cookies.get("AUTH_BINDING"));
        assertFalse(page.body.contains("j_csrf"));
        Matcher nonce = NONCE.matcher(page.body);
        assertEquals(true, nonce.find());

        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("j_username", "alice");
        fields.put("j_password", "pw");
        fields.put("j_code", TestServer.TOTP_CODE);
        fields.put("j_nonce", nonce.group(1));
        fields.put("back", "/app");
        Browser.Response login = browser.postForm("/auth/login", fields, null);
        assertEquals(302, login.status);
        assertNotNull(browser.cookies.get("AUTH_TOKEN"));

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Original-URI", "/app");
        headers.put("X-Policy-Id", "anything");
        assertEquals(200, browser.get("/auth/nginx-auth-request-check", headers).status);

        Browser anonymous = new Browser(server.port);
        Browser.Response denied = anonymous.get("/auth/nginx-auth-request-check", headers);
        assertEquals(401, denied.status);
        assertNull(denied.header("X-Login-Context"));

        assertEquals(200, browser.get("/auth/logout").status);
        assertEquals(401, browser.get("/auth/nginx-auth-request-check", headers).status);
    }
}
