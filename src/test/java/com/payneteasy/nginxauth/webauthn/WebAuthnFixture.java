package com.payneteasy.nginxauth.webauthn;

import com.payneteasy.nginxauth.ldap.LdapPrincipal;
import com.payneteasy.nginxauth.policy.PolicyResolver;
import com.payneteasy.nginxauth.policy.PolicySet;
import com.payneteasy.nginxauth.service.AuthenticationMethod;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.service.impl.TokenManagerImpl;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.Ceremony;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.FinishResult;
import com.payneteasy.nginxauth.webauthn.WebAuthnService.SessionIssued;
import com.payneteasy.nginxauth.webauthn.storage.FileCredentialRepository;
import com.payneteasy.nginxauth.webauthn.storage.UserLocks;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Wires the WebAuthn core with a temp storage directory and a controllable clock.
 */
public final class WebAuthnFixture {

    public static final String ORIGIN  = "https://app1.example.com";
    public static final String ORIGIN2 = "https://app2.example.com";

    public final AtomicLong now = new AtomicLong(1_800_000_000_000L);
    public final Path dir;
    public final WebAuthnConfig config;
    public FileCredentialRepository repository;
    public final TokenManagerImpl tokens;
    public final BrowserStateStore states;
    public final TransactionStore transactions;
    public final LoginContextStore contexts;
    public final PolicyResolver resolver;
    public WebAuthnService service;

    public WebAuthnFixture() throws Exception {
        this(PolicySet.EMPTY, WebAuthnConfig.CounterPolicy.REJECT);
    }

    public WebAuthnFixture(PolicySet aPolicies, WebAuthnConfig.CounterPolicy aCounterPolicy) throws Exception {
        dir = Files.createTempDirectory("webauthn-test").resolve("store");
        config = WebAuthnConfig.builder()
                .enabled(true)
                .rpId("example.com")
                .allowedOrigins(ORIGIN + "," + ORIGIN2)
                .storageDir(dir)
                .policies(aPolicies)
                .counterPolicy(aCounterPolicy)
                .build();
        tokens = new TokenManagerImpl(15 * 60 * 1000L, now::get);
        states = new BrowserStateStore(3_600_000L, 1000, now::get);
        transactions = new TransactionStore(1000, now::get);
        contexts = new LoginContextStore(config.getLoginContextTtlMillis(), 1000, now::get);
        resolver = new PolicyResolver(aPolicies);
        restart();
    }

    /** Re-opens storage from disk and drops in-memory ceremony state, like a process restart. */
    public void restart() throws Exception {
        repository = FileCredentialRepository.open(dir, new UserLocks());
        service = new WebAuthnService(config, repository, tokens, states, transactions, contexts, resolver, now::get);
    }

    public BrowserState browser() {
        return states.getOrCreate(null).orElseThrow();
    }

    public BrowserState ldapLogin(String aUid, List<String> aGroups, String aPolicyId) {
        BrowserState state = browser();
        ldapLogin(state, aUid, aGroups, aPolicyId);
        return state;
    }

    public PreAuth ldapLogin(BrowserState aState, String aUid, List<String> aGroups, String aPolicyId) {
        PreAuth pre = PreAuth.create(new LdapPrincipal(aUid, aUid + " name", aGroups, now.get()), aPolicyId, "/back");
        states.setPreAuth(aState, pre);
        return pre;
    }

    public String totpSession(String aUid, List<String> aGroups) {
        return tokens.createSession(Session.withoutWebAuthn(aUid, aUid, aGroups, AuthenticationMethod.LDAP_TOTP, now.get()));
    }

    /** Registers a credential through a bootstrap session. */
    public void bootstrap(String aUid, SoftAuthenticator aAuthenticator) throws WebAuthnException {
        BrowserState state = browser();
        String token = totpSession(aUid, List.of());
        Ceremony ceremony = service.startRegister(state, ORIGIN, token);
        service.finish(state, ORIGIN, token, "register", ceremony.transactionId(), aAuthenticator.create(ceremony.publicKeyJson(), ORIGIN), "key");
    }

    public String login(String aUid, SoftAuthenticator aAuthenticator) throws WebAuthnException {
        BrowserState state = ldapLogin(aUid, List.of(), "none");
        Ceremony ceremony = service.startLogin(state, ORIGIN);
        FinishResult result = service.finish(state, ORIGIN, null, "login", ceremony.transactionId(), aAuthenticator.get(ceremony.publicKeyJson(), ORIGIN), null);
        return ((SessionIssued) result).token();
    }

    public void deleteAll() throws IOException {
        if (Files.exists(dir)) {
            try (var walk = Files.walk(dir.getParent())) {
                walk.sorted((a, b) -> b.compareTo(a)).forEach(p -> p.toFile().delete());
            }
        }
    }
}
