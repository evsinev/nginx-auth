package com.payneteasy.nginxauth.policy;

import com.payneteasy.nginxauth.service.AuthenticationMethod;
import com.payneteasy.nginxauth.service.Session;
import org.junit.Test;

import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PolicyResolverTest {

    private static final String A1 = "cb69481e-8ff7-4039-93ec-0a2729a154a8";
    private static final String A2 = "ee882879-721c-4913-9775-3dfcce97072a";

    private static final String POLICY = "{\"version\":1,"
            + "\"groups\":{"
            + "  \"cn=admins,ou=groups,dc=example,dc=com\":{\"requireWebAuthn\":true},"
            + "  \"ops\":{\"requireSingleDeviceCredential\":true,\"allowedAaguids\":[\"" + A1 + "\",\"" + A2 + "\"],\"maxAuthAge\":900},"
            + "  \"yubi\":{\"allowedAaguids\":[\"" + A1.toUpperCase() + "\"],\"maxAuthAge\":600},"
            + "  \"other\":{\"allowedAaguids\":[\"" + A2 + "\"]}"
            + "},"
            + "\"locations\":{\"admin\":{\"requireWebAuthn\":true,\"maxAuthAge\":300}}}";

    private final PolicyResolver resolver = new PolicyResolver(PolicySet.parse(POLICY));

    @Test
    public void combinesByTheTable() {
        EffectivePolicy policy = resolver.resolve(List.of("cn=ops,ou=groups,dc=example,dc=com", "cn=yubi,ou=g"), "admin");
        assertTrue(policy.requireWebAuthn());
        assertTrue(policy.requireSingleDeviceCredential());
        assertEquals(Set.of(A1), policy.allowedAaguids());
        assertEquals(Long.valueOf(300), policy.maxAuthAgeSeconds());
        assertFalse(policy.denyAll());
    }

    @Test
    public void emptyAaguidIntersectionDeniesAll() {
        EffectivePolicy policy = resolver.resolve(List.of("cn=yubi,ou=g", "cn=other,ou=g"));
        assertTrue(policy.denyAll());
        assertFalse(policy.isEligible(false, A1));
    }

    @Test
    public void unsetIsNotEmpty() {
        EffectivePolicy policy = resolver.resolve(List.of("cn=admins,ou=groups,dc=example,dc=com"));
        assertNull(policy.allowedAaguids());
        assertTrue(policy.isEligible(true, "00000000-0000-0000-0000-000000000000"));
    }

    @Test
    public void requirementsImplyWebAuthn() {
        EffectivePolicy policy = EffectivePolicy.combine(List.of(new PolicyRule(false, false, null, 60L)));
        assertTrue(policy.requireWebAuthn());
    }

    @Test
    public void groupMatchingByDnAndLeftmostCn() {
        assertTrue(PolicyResolver.memberOf(List.of("CN=Admins,OU=Groups,DC=example,DC=com"), "cn=admins,ou=groups,dc=example,dc=com"));
        assertTrue(PolicyResolver.memberOf(List.of("cn=ops,ou=groups,dc=example,dc=com"), "ops"));
        assertFalse(PolicyResolver.memberOf(List.of("cn=x,ou=ops,dc=example,dc=com"), "ops"));
        assertFalse(PolicyResolver.memberOf(List.of("cn=dc,ou=g,dc=ops"), "ops"));
        assertTrue(PolicyResolver.memberOf(List.of("ops"), "ops"));
    }

    @Test
    public void knownPolicyIds() {
        assertTrue(resolver.isKnownPolicyId("admin"));
        assertTrue(resolver.isKnownPolicyId("none"));
        assertFalse(resolver.isKnownPolicyId("adminx"));
        assertFalse(resolver.isKnownPolicyId(""));
        assertFalse(resolver.isKnownPolicyId(null));
        try {
            resolver.resolve(List.of(), "adminx");
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        PolicyResolver noLocations = new PolicyResolver(PolicySet.parse("{\"version\":1,\"groups\":{}}"));
        assertTrue(noLocations.isKnownPolicyId(null));
        assertFalse(noLocations.resolve(List.of(), "anything").requireWebAuthn());
    }

    @Test
    public void strictParsing() {
        String[] bad = {
                "{\"version\":1,\"group\":{}}",
                "{\"groups\":{}}",
                "{\"version\":1,\"groups\":{\"g\":{\"requireWebauthn\":true}}}",
                "{\"version\":1,\"groups\":{\"g\":{\"requireWebAuthn\":\"yes\"}}}",
                "{\"version\":1,\"groups\":{\"g\":{\"allowedAaguids\":[\"nope\"]}}}",
                "{\"version\":1,\"groups\":{\"g\":{\"maxAuthAge\":0}}}",
                "{\"version\":1,\"groups\":{\"g\":{\"maxAuthAge\":1.5}}}",
                "{\"version\":1,\"locations\":{\"none\":{}}}",
                "{\"version\":1,\"locations\":{\"a b\":{}}}",
                "not json",
        };
        for (String json : bad) {
            try {
                PolicySet.parse(json);
                fail("accepted " + json);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
    }

    @Test
    public void accessCheckerDecisions() {
        AtomicLong now = new AtomicLong(1_000_000L);
        AccessChecker checker = new AccessChecker(resolver, null, now::get);
        Session totp = Session.withoutWebAuthn("alice", "alice", List.of("cn=admins,ou=groups,dc=example,dc=com"), AuthenticationMethod.LDAP_TOTP, now.get());
        assertEquals(AccessChecker.Decision.STEP_UP, checker.check(totp, "none"));
        Session plain = Session.withoutWebAuthn("bob", "bob", List.of(), AuthenticationMethod.LDAP_ONLY, now.get());
        assertEquals(AccessChecker.Decision.ALLOW, checker.check(plain, "none"));
        assertEquals(AccessChecker.Decision.STEP_UP, checker.check(plain, "admin"));
        Session denied = Session.withoutWebAuthn("carol", "carol", List.of("cn=yubi,ou=g", "cn=other,ou=g"), AuthenticationMethod.LDAP_TOTP, now.get());
        assertEquals(AccessChecker.Decision.DENY, checker.check(denied, "none"));
    }
}
