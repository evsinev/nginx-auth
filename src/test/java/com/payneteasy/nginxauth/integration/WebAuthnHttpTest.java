package com.payneteasy.nginxauth.integration;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.payneteasy.nginxauth.policy.PolicySet;
import com.payneteasy.nginxauth.service.AuthenticationMethod;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.webauthn.SoftAuthenticator;
import org.junit.After;
import org.junit.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class WebAuthnHttpTest {

    private static final String STRICT_POLICY = "{\"version\":1,"
            + "\"groups\":{\"admins\":{\"requireWebAuthn\":true}},"
            + "\"locations\":{\"admin\":{\"requireWebAuthn\":true}}}";

    private TestServer server;

    @After
    public void tearDown() throws Exception {
        if (server != null) {
            server.close();
        }
    }

    private TestServer start(String aPolicy, boolean aOtpEnabled) throws Exception {
        server = new TestServer(true, aPolicy == null ? PolicySet.EMPTY : PolicySet.parse(aPolicy), aOtpEnabled);
        return server;
    }

    private Browser browser() {
        return new Browser(server.port);
    }

    private static Map<String, String> form(String... aPairs) {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i < aPairs.length; i += 2) {
            map.put(aPairs[i], aPairs[i + 1]);
        }
        return map;
    }

    private static Browser.Response login(Browser aBrowser, String aQuery, String aUser, String aPassword, String aCode) throws Exception {
        Browser.Response page = aBrowser.get("/auth?" + aQuery);
        assertEquals(200, page.status);
        Map<String, String> fields = form("j_username", aUser, "j_password", aPassword, "j_code", aCode == null ? "" : aCode,
                "j_csrf", page.csrf());
        if (aQuery.startsWith("ctx=")) {
            fields.put("ctx", aQuery.substring(4));
        } else {
            fields.put("back", java.net.URLDecoder.decode(aQuery.substring(5), java.nio.charset.StandardCharsets.UTF_8));
        }
        return aBrowser.postForm("/auth/login", fields);
    }

    /** Runs start → (get|create) → finish, following chained ceremonies; one authenticator per ceremony. */
    private static JsonObject ceremony(Browser aBrowser, String aCsrf, JsonObject aStart, SoftAuthenticator... aKeys) throws Exception {
        Browser.Response response = aBrowser.postJson("/auth/webauthn/start", aStart, aCsrf);
        assertEquals(response.body, 200, response.status);
        JsonObject step = response.json().getAsJsonObject("ceremony");
        for (int i = 0; ; i++) {
            String options = "{\"publicKey\":" + step.get("publicKey") + "}";
            SoftAuthenticator key = aKeys[Math.min(i, aKeys.length - 1)];
            String credential = "create".equals(step.get("type").getAsString())
                    ? key.create(options, aBrowser.origin)
                    : key.get(options, aBrowser.origin);
            JsonObject finish = new JsonObject();
            finish.addProperty("transactionId", step.get("transactionId").getAsString());
            finish.addProperty("purpose", step.get("purpose").getAsString());
            finish.add("credential", JsonParser.parseString(credential));
            finish.addProperty("name", "key " + i);
            Browser.Response done = aBrowser.postJson("/auth/webauthn/finish", finish, aCsrf);
            JsonObject json = done.json();
            if (done.status != 200 || !json.has("ceremony")) {
                json.addProperty("status", done.status);
                return json;
            }
            step = json.getAsJsonObject("ceremony");
        }
    }

    private static JsonObject purpose(String aPurpose) {
        JsonObject body = new JsonObject();
        body.addProperty("purpose", aPurpose);
        return body;
    }

    private Session session(Browser aBrowser) {
        return server.app.tokens().peekSession(aBrowser.cookies.get("AUTH_TOKEN")).orElse(null);
    }

    private Browser.Response authRequest(Browser aBrowser, String aPolicyId, String aUri) throws Exception {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-Original-URI", aUri);
        if (aPolicyId != null) {
            headers.put("X-Policy-Id", aPolicyId);
        }
        return aBrowser.get("/auth/nginx-auth-request-check", headers);
    }

    /** TOTP login, then bootstrap registration from the credentials page. */
    private void enroll(String aUser, SoftAuthenticator aKey) throws Exception {
        Browser browser = browser();
        Browser.Response response = login(browser, "back=%2Fapp", aUser, "pw", TestServer.TOTP_CODE);
        assertEquals(302, response.status);
        Browser.Response page = browser.get("/auth/credentials");
        assertEquals(200, page.status);
        JsonObject result = ceremony(browser, page.csrf(), purpose("register"), aKey);
        assertTrue(result.toString(), result.get("ok").getAsBoolean());
    }

    // ------------------------------------------------------------------ flows

    @Test
    public void totpLoginBootstrapThenWebAuthnLogin() throws Exception {
        start(null, true);
        server.user("alice", "pw");
        server.totpUsers.put("alice", true);
        SoftAuthenticator key = new SoftAuthenticator();
        enroll("alice", key);

        Browser browser = browser();
        Browser.Response response = login(browser, "back=%2Fapp", "alice", "pw", null);
        assertEquals(303, response.status);
        assertEquals("/auth/verify", response.header("Location"));
        assertNull(browser.cookies.get("AUTH_TOKEN"));

        Browser.Response verify = browser.get("/auth/verify");
        assertTrue(verify.body.contains("data-mode=\"login\""));
        key.signCount = 1;
        JsonObject result = ceremony(browser, verify.csrf(), purpose("login"), key);
        assertEquals("/app", result.get("redirect").getAsString());
        assertEquals(AuthenticationMethod.LDAP_WEBAUTHN, session(browser).getMethod());
        assertEquals(200, authRequest(browser, null, "/app").status);

        // the same credential works on another host of the same RP ID
        Browser other = browser();
        other.host = "app2.example.com";
        other.origin = "https://app2.example.com";
        assertEquals(303, login(other, "back=%2Fapp", "alice", "pw", null).status);
        key.signCount = 2;
        JsonObject second = ceremony(other, other.get("/auth/verify").csrf(), purpose("login"), key);
        assertEquals("/app", second.get("redirect").getAsString());
    }

    @Test
    public void secondKeyNeedsConfirmationWithFirst() throws Exception {
        start(null, true);
        server.user("bob", "pw");
        server.totpUsers.put("bob", true);
        SoftAuthenticator first = new SoftAuthenticator();
        enroll("bob", first);

        Browser browser = browser();
        login(browser, "back=%2Fapp", "bob", "pw", TestServer.TOTP_CODE);
        Browser.Response page = browser.get("/auth/credentials");
        first.signCount = 1;
        SoftAuthenticator second = new SoftAuthenticator();
        JsonObject result = ceremony(browser, page.csrf(), purpose("register"), first, second);
        assertTrue(result.toString(), result.get("ok").getAsBoolean());
        assertEquals(2, server.webauthn.repository().find("bob").orElseThrow().credentials().size());
    }

    // ------------------------------------------------------------------ CSRF / Origin

    @Test
    public void postWithoutOrForeignOriginIsRejected() throws Exception {
        start(null, true);
        server.user("carol", "pw");
        Browser browser = browser();
        String csrf = browser.get("/auth?back=%2Fapp").csrf();
        Map<String, String> fields = form("j_username", "carol", "j_password", "pw", "j_csrf", csrf, "back", "/app");
        assertEquals(403, browser.postForm("/auth/login", fields, null).status);
        assertEquals(403, browser.postForm("/auth/login", fields, "https://evil.example.com").status);
        assertEquals(403, browser.postForm("/auth/login", fields, "https://app2.example.com").status);

        JsonObject start = purpose("login");
        Browser.Response api = browser.postJson("/auth/webauthn/start", start, null);
        assertEquals(403, api.status);
    }

    @Test
    public void csrfTokenFromAnotherBrowserIsRejected() throws Exception {
        start(null, false);
        server.user("dave", "pw");
        Browser victim = browser();
        Browser attacker = browser();
        attacker.get("/auth?back=%2Fapp");
        String attackerToken = attacker.get("/auth?back=%2Fapp").csrf();
        victim.get("/auth?back=%2Fapp");
        Browser.Response response = victim.postForm("/auth/login",
                form("j_username", "dave", "j_password", "pw", "j_csrf", attackerToken, "back", "/app"));
        assertEquals(200, response.status);
        assertTrue(response.body.contains("expired"));
        assertNull(victim.cookies.get("AUTH_TOKEN"));
    }

    @Test
    public void unknownHostIsRejected() throws Exception {
        start(null, false);
        Browser browser = browser();
        browser.host = "evil.example.net";
        assertEquals(403, browser.get("/auth?back=%2Fapp").status);
    }

    // ------------------------------------------------------------------ policy

    @Test
    public void strictLocationNeedsStepUpAndRotatesToken() throws Exception {
        start(STRICT_POLICY, true);
        server.user("erin", "pw");
        server.totpUsers.put("erin", true);
        SoftAuthenticator key = new SoftAuthenticator();
        enroll("erin", key);

        Browser browser = browser();
        assertEquals(302, login(browser, "back=%2Fapp", "erin", "pw", TestServer.TOTP_CODE).status);
        String totpToken = browser.cookies.get("AUTH_TOKEN");
        assertEquals(200, authRequest(browser, "none", "/app").status);

        Browser.Response denied = authRequest(browser, "admin", "/admin/x");
        assertEquals(401, denied.status);
        String contextId = denied.header("X-Login-Context");
        assertNotNull(contextId);

        Browser.Response stepUp = browser.get("/auth?ctx=" + contextId);
        assertTrue(stepUp.body, stepUp.body.contains("data-mode=\"step_up\""));
        JsonObject start = purpose("step_up");
        start.addProperty("contextId", contextId);
        key.signCount = 1;
        JsonObject result = ceremony(browser, stepUp.csrf(), start, key);
        assertEquals("/admin/x", result.get("redirect").getAsString());

        String newToken = browser.cookies.get("AUTH_TOKEN");
        assertFalse(newToken.equals(totpToken));
        assertFalse(server.app.tokens().peekSession(totpToken).isPresent());
        assertEquals(200, authRequest(browser, "admin", "/admin/x").status);
    }

    @Test
    public void contextFromOtherBrowserIsRejected() throws Exception {
        start(STRICT_POLICY, true);
        Browser owner = browser();
        Browser.Response denied = authRequest(owner, "admin", "/admin/x");
        String contextId = denied.header("X-Login-Context");
        assertEquals(200, owner.get("/auth?ctx=" + contextId).status);
        Browser other = browser();
        assertEquals(400, other.get("/auth?ctx=" + contextId).status);
        assertEquals(400, other.get("/auth?ctx=").status);
    }

    @Test
    public void unknownOrMissingPolicyIdIsForbidden() throws Exception {
        start(STRICT_POLICY, true);
        Browser browser = browser();
        assertEquals(403, authRequest(browser, "nope", "/x").status);
        assertEquals(403, authRequest(browser, null, "/x").status);
        assertEquals(401, authRequest(browser, "none", "/x").status);
    }

    @Test
    public void contextKeepsPolicyOfStrictLocation() throws Exception {
        start(STRICT_POLICY, true);
        server.user("frank", "pw");
        server.totpUsers.put("frank", true);
        Browser browser = browser();
        String contextId = authRequest(browser, "admin", "/admin/x").header("X-Login-Context");
        Browser.Response response = login(browser, "ctx=" + contextId, "frank", "pw", TestServer.TOTP_CODE);
        // TOTP is not enough for the admin location: no session, second factor page instead
        assertEquals(303, response.status);
        assertNull(browser.cookies.get("AUTH_TOKEN"));
    }

    @Test
    public void requiredWebAuthnIgnoresTotpAndPasswordChange() throws Exception {
        start(STRICT_POLICY, true);
        server.user("gina", "pw", "cn=admins,ou=groups,dc=example,dc=com");
        server.totpUsers.put("gina", true);
        Browser browser = browser();
        Browser.Response response = login(browser, "back=%2Fapp", "gina", "pw", TestServer.TOTP_CODE);
        assertEquals(303, response.status);
        assertNull(browser.cookies.get("AUTH_TOKEN"));
        Browser.Response verify = browser.get("/auth/verify");
        assertTrue(verify.body.contains("data-mode=\"recovery\""));

        server.mustChange.put("gina", true);
        Browser changer = browser();
        String csrf = changer.get("/auth?back=%2Fapp").csrf();
        Browser.Response changed = changer.postForm("/auth/change-password", form(
                "j_username", "gina", "j_password", "pw", "j_password_new_1", "pw2", "j_password_new_2", "pw2",
                "j_code", TestServer.TOTP_CODE, "j_csrf", csrf, "back", "/app"));
        assertEquals(303, changed.status);
        assertEquals("pw2", server.passwords.get("gina"));
        assertNull(changer.cookies.get("AUTH_TOKEN"));
    }

    @Test
    public void passwordChangeRevokesExistingSessions() throws Exception {
        start(null, true);
        server.user("nora", "pw");
        server.totpUsers.put("nora", true);
        Browser stolen = browser();
        assertEquals(302, login(stolen, "back=%2Fapp", "nora", "pw", TestServer.TOTP_CODE).status);
        assertEquals(200, authRequest(stolen, null, "/app").status);

        Browser owner = browser();
        String csrf = owner.get("/auth?back=%2Fapp").csrf();
        Browser.Response changed = owner.postForm("/auth/change-password", form(
                "j_username", "nora", "j_password", "pw", "j_password_new_1", "pw2", "j_password_new_2", "pw2",
                "j_code", TestServer.TOTP_CODE, "j_csrf", csrf, "back", "/app"));
        assertEquals(302, changed.status);
        assertEquals(401, authRequest(stolen, null, "/app").status);
        assertEquals(200, authRequest(owner, null, "/app").status);
    }

    @Test
    public void passwordChangeRevokesSessionsEvenIfReloginFails() throws Exception {
        start(null, true);
        server.user("olga", "pw");
        server.totpUsers.put("olga", true);
        Browser stolen = browser();
        assertEquals(302, login(stolen, "back=%2Fapp", "olga", "pw", TestServer.TOTP_CODE).status);

        server.failPrincipalAfterChange = true;
        Browser owner = browser();
        String csrf = owner.get("/auth?back=%2Fapp").csrf();
        Browser.Response changed = owner.postForm("/auth/change-password", form(
                "j_username", "olga", "j_password", "pw", "j_password_new_1", "pw2", "j_password_new_2", "pw2",
                "j_code", TestServer.TOTP_CODE, "j_csrf", csrf, "back", "/app"));
        assertTrue(changed.body.contains("Password changed"));
        assertNull(owner.cookies.get("AUTH_TOKEN"));
        assertEquals(401, authRequest(stolen, null, "/app").status);
    }

    @Test
    public void forcedPasswordChangeRevokesByLoginNameWhenUidIsUnreadable() throws Exception {
        start(null, true);
        server.user("Olga Smith", "pw");
        server.uids.put("Olga Smith", "osmith");
        server.totpUsers.put("Olga Smith", true);
        Browser stolen = browser();
        assertEquals(302, login(stolen, "back=%2Fapp", "Olga Smith", "pw", TestServer.TOTP_CODE).status);
        assertEquals("osmith", session(stolen).getCanonicalUid());

        // expired password: uid not readable before the change, re-reading it fails after the change
        server.mustChange.put("Olga Smith", true);
        server.failPrincipalAfterChange = true;
        Browser owner = browser();
        String csrf = owner.get("/auth?back=%2Fapp").csrf();
        Browser.Response changed = owner.postForm("/auth/change-password", form(
                "j_username", "Olga Smith", "j_password", "pw", "j_password_new_1", "pw2", "j_password_new_2", "pw2",
                "j_code", TestServer.TOTP_CODE, "j_csrf", csrf, "back", "/app"));
        assertTrue(changed.body.contains("Password changed"));
        assertEquals(401, authRequest(stolen, null, "/app").status);
    }

    @Test
    public void otherSpellingCannotSkipTotpOnPasswordChange() throws Exception {
        start(null, true);
        server.user("Olga Smith", "pw");
        server.totpUsers.put("Olga Smith", true);
        Browser attacker = browser();
        String csrf = attacker.get("/auth?back=%2Fapp").csrf();
        Browser.Response response = attacker.postForm("/auth/change-password", form(
                "j_username", "olga  SMITH", "j_password", "pw", "j_password_new_1", "pw2", "j_password_new_2", "pw2",
                "j_csrf", csrf, "back", "/app"));
        assertTrue(response.body.contains("Verification code is empty"));
        assertEquals("pw", server.passwords.get("Olga Smith"));

        server.user("Straße", "pw");
        server.totpUsers.put("Straße", true);
        Browser.Response folded = attacker.postForm("/auth/change-password", form(
                "j_username", "STRASSE", "j_password", "pw", "j_password_new_1", "pw2", "j_password_new_2", "pw2",
                "j_csrf", attacker.get("/auth?back=%2Fapp").csrf(), "back", "/app"));
        assertTrue(folded.body.contains("Verification code is empty"));
        assertEquals("pw", server.passwords.get("Straße"));
    }

    @Test
    public void totpOfAnotherSpellingIsNeverUsed() throws Exception {
        start(null, true);
        server.user("Olga Smith", "pw");
        server.totpUsers.put("Olga Smith", true);
        Browser browser = browser();
        // LDAP accepts the spelling, but the TOTP secret is looked up by the exact name only
        Browser.Response response = login(browser, "back=%2Fapp", "olga smith", "pw", TestServer.TOTP_CODE);
        assertEquals(200, response.status);
        assertNull(browser.cookies.get("AUTH_TOKEN"));
    }

    @Test
    public void securityKeyUserChangesPasswordWithoutTotp() throws Exception {
        start(null, true);
        server.user("pete", "pw");
        server.totpUsers.put("pete", true);
        enroll("pete", new SoftAuthenticator());
        server.totpUsers.remove("pete");
        Browser browser = browser();
        String csrf = browser.get("/auth?back=%2Fapp").csrf();
        Browser.Response changed = browser.postForm("/auth/change-password", form(
                "j_username", "pete", "j_password", "pw", "j_password_new_1", "pw2", "j_password_new_2", "pw2",
                "j_csrf", csrf, "back", "/app"));
        assertEquals(303, changed.status);
        assertEquals("pw2", server.passwords.get("pete"));
        assertNull(browser.cookies.get("AUTH_TOKEN"));
    }

    @Test
    public void recoveryOverHttp() throws Exception {
        start(STRICT_POLICY, false);
        server.user("hank", "pw", "cn=admins,ou=groups,dc=example,dc=com");
        String secret = adminCall("POST", "/admin/webauthn/grant", "{\"uid\":\"hank\",\"issuedBy\":\"it\"}", TestServer.ADMIN_TOKEN)
                .get("secret").getAsString();

        Browser browser = browser();
        assertEquals(303, login(browser, "back=%2Fapp", "hank", "pw", null).status);
        String csrf = browser.get("/auth/verify").csrf();
        assertEquals(403, browser.postJson("/auth/webauthn/start", purpose("recovery_enroll"), "wrong").status);
        Browser.Response noPermit = browser.postJson("/auth/webauthn/start", purpose("recovery_enroll"), csrf);
        assertEquals(400, noPermit.status);

        Browser.Response accepted = browser.postForm("/auth/recovery", form("j_secret", secret, "j_csrf", csrf));
        assertEquals(303, accepted.status);
        Browser.Response enroll = browser.get("/auth/verify");
        assertTrue(enroll.body.contains("data-mode=\"recovery_enroll\""));
        SoftAuthenticator key = new SoftAuthenticator();
        JsonObject result = ceremony(browser, csrf, purpose("recovery_enroll"), key);
        assertEquals("/app", result.get("redirect").getAsString());
        assertEquals(AuthenticationMethod.LDAP_WEBAUTHN, session(browser).getMethod());
    }

    @Test
    public void directLoginWithoutBackGoesToRoot() throws Exception {
        start(null, false);
        server.user("kate", "pw");
        Browser browser = browser();
        Browser.Response page = browser.get("/auth");
        assertFalse(page.body.contains("Bad back url"));
        Browser.Response response = browser.postForm("/auth/login",
                form("j_username", "kate", "j_password", "pw", "j_csrf", page.csrf(), "back", "/"));
        assertEquals(302, response.status);
        assertTrue(response.header("Location").endsWith("/"));
    }

    @Test
    public void unavailableStorageDoesNotFallBackToPasswordOnly() throws Exception {
        start(null, false);
        server.user("liam", "pw");
        java.lang.reflect.Field failed = server.webauthn.repository().getClass().getDeclaredField("failed");
        failed.setAccessible(true);
        failed.set(server.webauthn.repository(), true);
        Browser browser = browser();
        Browser.Response response = login(browser, "back=%2Fapp", "liam", "pw", null);
        assertEquals(200, response.status);
        assertTrue(response.body.contains("Internal error"));
        assertNull(browser.cookies.get("AUTH_TOKEN"));
    }

    @Test
    public void recoveryAfterResetForOptionalWebAuthnUser() throws Exception {
        start(null, true);
        server.user("mia", "pw");
        String secret = adminCall("POST", "/admin/webauthn/reset", "{\"uid\":\"mia\",\"grant\":true,\"issuedBy\":\"it\"}", TestServer.ADMIN_TOKEN)
                .get("secret").getAsString();
        Browser browser = browser();
        Browser.Response response = login(browser, "back=%2Fapp", "mia", "pw", null);
        assertEquals(303, response.status);
        String csrf = browser.get("/auth/verify").csrf();
        assertEquals(303, browser.postForm("/auth/recovery", form("j_secret", secret, "j_csrf", csrf)).status);
        JsonObject result = ceremony(browser, csrf, purpose("recovery_enroll"), new SoftAuthenticator());
        assertEquals("/app", result.get("redirect").getAsString());
        assertEquals(AuthenticationMethod.LDAP_WEBAUTHN, session(browser).getMethod());
    }

    // ------------------------------------------------------------------ logout and admin

    @Test
    public void logoutNeedsPostWithCsrf() throws Exception {
        start(null, false);
        server.user("ivan", "pw");
        Browser browser = browser();
        assertEquals(302, login(browser, "back=%2Fapp", "ivan", "pw", null).status);
        String token = browser.cookies.get("AUTH_TOKEN");
        Browser.Response confirm = browser.get("/auth/logout");
        assertTrue(server.app.tokens().peekSession(token).isPresent());
        assertEquals(403, browser.postForm("/auth/logout", form("j_csrf", "nope")).status);
        assertTrue(server.app.tokens().peekSession(token).isPresent());
        assertEquals(200, browser.postForm("/auth/logout", form("j_csrf", confirm.csrf())).status);
        assertFalse(server.app.tokens().peekSession(token).isPresent());
    }

    @Test
    public void adminApiOnlyOnAdminConnectorWithAdminToken() throws Exception {
        start(null, false);
        server.user("judy", "pw");
        Browser browser = browser();
        login(browser, "back=%2Fapp", "judy", "pw", null);
        String token = browser.cookies.get("AUTH_TOKEN");

        HttpResponse<String> onMain = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + server.port + "/admin/webauthn/user?uid=judy"))
                .header("Authorization", "Bearer " + TestServer.ADMIN_TOKEN).build(), HttpResponse.BodyHandlers.ofString());
        assertFalse(onMain.body().contains("\"ok\""));

        assertEquals(401, adminStatus("GET", "/admin/webauthn/user?uid=judy", null, "Bearer api-check-token"));
        adminCall("POST", "/admin/webauthn/reset", "{\"uid\":\"judy\",\"issuedBy\":\"it\"}", TestServer.ADMIN_TOKEN);
        assertFalse(server.app.tokens().peekSession(token).isPresent());

        HttpResponse<String> authOnAdmin = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + server.adminPort + "/auth?back=%2F")).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(404, authOnAdmin.statusCode());
    }

    private JsonObject adminCall(String aMethod, String aPath, String aBody, String aToken) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.adminPort + aPath))
                .header("Authorization", "Bearer " + aToken)
                .header("Content-Type", "application/json");
        builder.method(aMethod, aBody == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(aBody));
        HttpResponse<String> response = HttpClient.newHttpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(response.body(), 200, response.statusCode());
        return JsonParser.parseString(response.body()).getAsJsonObject();
    }

    private int adminStatus(String aMethod, String aPath, String aBody, String aAuthorization) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.adminPort + aPath))
                .header("Authorization", aAuthorization);
        builder.method(aMethod, aBody == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(aBody));
        return HttpClient.newHttpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString()).statusCode();
    }
}
