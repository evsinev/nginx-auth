package com.payneteasy.nginxauth.webauthn;

import com.payneteasy.nginxauth.policy.PolicySet;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class WebAuthnConfigTest {

    private static WebAuthnConfig.Builder valid() {
        return WebAuthnConfig.builder().enabled(true).rpId("example.com").allowedOrigins("https://app1.example.com,https://example.com:8443");
    }

    private static void expectError(String aMessagePart, WebAuthnConfig.Builder aBuilder) {
        try {
            aBuilder.build();
            fail("expected configuration error");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(aMessagePart));
        }
    }

    @Test
    public void validConfiguration() {
        WebAuthnConfig config = valid().build();
        assertEquals(2, config.getAllowedOrigins().size());
        assertEquals("https://example.com:8443", config.getAllowedOrigins().get(1).getOrigin());
    }

    @Test
    public void disabledWithWebAuthnPolicyIsAnError() {
        PolicySet policies = PolicySet.parse("{\"version\":1,\"groups\":{\"g\":{\"maxAuthAge\":60}}}");
        expectError("WEBAUTHN_ENABLED=false", WebAuthnConfig.builder().enabled(false).policies(policies));
        WebAuthnConfig.builder().enabled(false).policies(PolicySet.parse("{\"version\":1,\"groups\":{\"g\":{}}}")).build();
    }

    @Test
    public void originMustBeUnderRpId() {
        expectError("not WEBAUTHN_RP_ID", valid().allowedOrigins("https://example.org"));
        expectError("not WEBAUTHN_RP_ID", valid().allowedOrigins("https://badexample.com"));
    }

    @Test
    public void originFormat() {
        String[] bad = {"http://app1.example.com", "https://app1.example.com/path", "https://u@app1.example.com",
                "https://app1.example.com?q", "https://app1.example.com#f", "ftp://app1.example.com"};
        for (String origin : bad) {
            try {
                WebAuthnConfig.parseOrigins(origin);
                fail("accepted " + origin);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        try {
            WebAuthnConfig.parseOrigins("https://app1.example.com,https://APP1.example.com:443");
            fail("duplicate accepted");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("Duplicate"));
        }
    }

    @Test
    public void requiredSettings() {
        expectError("WEBAUTHN_RP_ID", WebAuthnConfig.builder().enabled(true).allowedOrigins("https://example.com"));
        expectError("WEBAUTHN_ALLOWED_ORIGINS", WebAuthnConfig.builder().enabled(true).rpId("example.com"));
        expectError("WEBAUTHN_ADMIN_TOKEN", valid().adminToken("short"));
        try {
            WebAuthnConfig.parseCounterPolicy("sometimes");
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    @Test
    public void hostHeaderMatching() {
        AllowedOrigin origin = AllowedOrigin.parse("https://app1.example.com");
        assertTrue(origin.matchesHostHeader("app1.example.com"));
        assertTrue(origin.matchesHostHeader("app1.example.com:443"));
        assertTrue(origin.matchesHostHeader("APP1.example.com"));
        assertFalse(origin.matchesHostHeader("app1.example.com:8443"));
        assertFalse(origin.matchesHostHeader("app2.example.com"));
        assertFalse(origin.matchesHostHeader(null));
        AllowedOrigin custom = AllowedOrigin.parse("https://example.com:8443");
        assertTrue(custom.matchesHostHeader("example.com:8443"));
        assertFalse(custom.matchesHostHeader("example.com"));
    }

    @Test
    public void storesAndStateCaps() {
        java.util.concurrent.atomic.AtomicLong now = new java.util.concurrent.atomic.AtomicLong(1000L);
        LoginContextStore contexts = new LoginContextStore(100L, 2, now::get);
        String c1 = contexts.create("admin", "/a", "https://app1.example.com").orElseThrow();
        contexts.create("admin", "/b", "https://app1.example.com").orElseThrow();
        assertFalse(contexts.create("admin", "/c", "https://app1.example.com").isPresent());
        assertFalse(contexts.claim(c1, "b1", "https://app2.example.com").isPresent());
        assertTrue(contexts.claim(c1, "b1", "https://app1.example.com").isPresent());
        assertTrue(contexts.claim(c1, "b1", "https://app1.example.com").isPresent());
        assertFalse(contexts.claim(c1, "b2", "https://app1.example.com").isPresent());
        now.addAndGet(200L);
        assertFalse(contexts.claim(c1, "b1", "https://app1.example.com").isPresent());
        assertTrue(contexts.create("admin", "/d", "https://app1.example.com").isPresent());

        BrowserStateStore states = new BrowserStateStore(100L, 1, now::get);
        BrowserStateStore.BrowserState state = states.getOrCreate(null).orElseThrow();
        assertFalse(states.getOrCreate(null).isPresent());
        assertTrue(states.checkCsrf(state, state.csrfToken()));
        assertFalse(states.checkCsrf(state, "x"));
        now.addAndGet(200L);
        assertFalse(states.get(state.binding()).isPresent());
        assertTrue(states.getOrCreate(null).isPresent());
    }
}
