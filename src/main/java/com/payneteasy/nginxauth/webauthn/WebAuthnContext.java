package com.payneteasy.nginxauth.webauthn;

import com.payneteasy.nginxauth.policy.AccessChecker;
import com.payneteasy.nginxauth.policy.PolicyResolver;
import com.payneteasy.nginxauth.service.ITokenManager;
import com.payneteasy.nginxauth.webauthn.storage.FileCredentialRepository;
import com.payneteasy.nginxauth.webauthn.storage.IWebAuthnCredentialRepository;
import com.payneteasy.nginxauth.webauthn.storage.StorageException;
import com.payneteasy.nginxauth.webauthn.storage.UserLocks;

import java.util.function.LongSupplier;

/**
 * Everything the web layer needs when WebAuthn is enabled.
 */
public final class WebAuthnContext {

    static final long BROWSER_STATE_IDLE_MILLIS = 60 * 60 * 1000L;
    static final int  BROWSER_STATE_CAP         = 20_000;
    static final int  LOGIN_CONTEXT_CAP         = 10_000;
    static final int  TRANSACTION_CAP           = 10_000;

    private final WebAuthnConfig                config;
    private final IWebAuthnCredentialRepository repository;
    private final BrowserStateStore             states;
    private final LoginContextStore             contexts;
    private final TransactionStore              transactions;
    private final PolicyResolver                resolver;
    private final OriginResolver                origins;
    private final WebAuthnService               service;

    public WebAuthnContext(WebAuthnConfig aConfig, IWebAuthnCredentialRepository aRepository, ITokenManager aTokens, LongSupplier aClock) {
        config       = aConfig;
        repository   = aRepository;
        states       = new BrowserStateStore(BROWSER_STATE_IDLE_MILLIS, BROWSER_STATE_CAP, aClock);
        contexts     = new LoginContextStore(aConfig.getLoginContextTtlMillis(), LOGIN_CONTEXT_CAP, aClock);
        transactions = new TransactionStore(TRANSACTION_CAP, aClock);
        resolver     = new PolicyResolver(aConfig.getPolicies());
        origins      = new OriginResolver(aConfig.getAllowedOrigins());
        service      = new WebAuthnService(aConfig, aRepository, aTokens, states, transactions, contexts, resolver, aClock);
    }

    public static WebAuthnContext open(WebAuthnConfig aConfig, ITokenManager aTokens) throws StorageException {
        FileCredentialRepository repository = FileCredentialRepository.open(aConfig.getStorageDir(), new UserLocks());
        return new WebAuthnContext(aConfig, repository, aTokens, System::currentTimeMillis);
    }

    public WebAuthnConfig config() {
        return config;
    }

    public IWebAuthnCredentialRepository repository() {
        return repository;
    }

    public BrowserStateStore states() {
        return states;
    }

    public LoginContextStore contexts() {
        return contexts;
    }

    public TransactionStore transactions() {
        return transactions;
    }

    public PolicyResolver resolver() {
        return resolver;
    }

    public OriginResolver origins() {
        return origins;
    }

    public WebAuthnService service() {
        return service;
    }

    public AccessChecker accessChecker() {
        return service.accessChecker();
    }
}
