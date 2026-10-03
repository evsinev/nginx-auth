package com.payneteasy.nginxauth.webauthn;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.payneteasy.nginxauth.policy.AccessChecker;
import com.payneteasy.nginxauth.policy.EffectivePolicy;
import com.payneteasy.nginxauth.policy.PolicyResolver;
import com.payneteasy.nginxauth.service.AuthenticationMethod;
import com.payneteasy.nginxauth.service.ITokenManager;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.webauthn.BrowserStateStore.BrowserState;
import com.payneteasy.nginxauth.webauthn.LoginContextStore.LoginContext;
import com.payneteasy.nginxauth.webauthn.storage.DuplicateCredentialException;
import com.payneteasy.nginxauth.webauthn.storage.EnrollmentGrant;
import com.payneteasy.nginxauth.webauthn.storage.FileCredentialRepository;
import com.payneteasy.nginxauth.webauthn.storage.IWebAuthnCredentialRepository;
import com.payneteasy.nginxauth.webauthn.storage.StorageException;
import com.payneteasy.nginxauth.webauthn.storage.StoredCredential;
import com.payneteasy.nginxauth.webauthn.storage.UserLocks;
import com.payneteasy.nginxauth.webauthn.storage.UserRecord;
import com.payneteasy.nginxauth.webauthn.storage.YubicoRepositoryAdapter;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * WebAuthn ceremonies. Cryptographic verification runs outside {@code lock(uid)}; every re-check against
 * current state and the publication of the result (session, credential, deletion) happen inside one
 * {@code lock(uid)} block, which logout, reset and session rotation also take.
 */
public final class WebAuthnService {

    private static final Logger LOG = LoggerFactory.getLogger(WebAuthnService.class);

    static final int    MAX_NAME_LENGTH = 64;
    static final String DEFAULT_NAME    = "Security key";
    static final int    USER_HANDLE_BYTES = 64;
    static final int    MAX_CREDENTIALS = 20;
    static final java.util.Set<String> KNOWN_TRANSPORTS = java.util.Set.of("usb", "nfc", "ble", "hybrid", "internal", "smart-card");

    public record Ceremony(String transactionId, String type, String publicKeyJson) {
    }

    public sealed interface FinishResult permits SessionIssued, NextCeremony, Done {
    }

    public record SessionIssued(String token, String back) implements FinishResult {
    }

    public record NextCeremony(Ceremony ceremony) implements FinishResult {
    }

    public record Done(String message) implements FinishResult {
    }

    private final WebAuthnConfig                config;
    private final IWebAuthnCredentialRepository repository;
    private final ITokenManager                 tokens;
    private final BrowserStateStore             states;
    private final TransactionStore              transactions;
    private final LoginContextStore             contexts;
    private final PolicyResolver                resolver;
    private final AccessChecker                 accessChecker;
    private final RelyingParties                relyingParties;
    private final LongSupplier                  clock;
    private final ConcurrentHashMap<String, Long> resetEpochs = new ConcurrentHashMap<>();

    /** Test hook: runs inside lock(uid) right before a ceremony result is committed. */
    volatile Runnable beforeCommitHook = () -> { };

    public WebAuthnService(WebAuthnConfig aConfig, IWebAuthnCredentialRepository aRepository, ITokenManager aTokens,
                           BrowserStateStore aStates, TransactionStore aTransactions, LoginContextStore aContexts,
                           PolicyResolver aResolver, LongSupplier aClock) {
        config         = aConfig;
        repository     = aRepository;
        tokens         = aTokens;
        states         = aStates;
        transactions   = aTransactions;
        contexts       = aContexts;
        resolver       = aResolver;
        clock          = aClock;
        accessChecker  = new AccessChecker(aResolver, aRepository, aClock);
        relyingParties = new RelyingParties(aConfig, new YubicoRepositoryAdapter(aRepository));
    }

    public AccessChecker accessChecker() {
        return accessChecker;
    }

    public IWebAuthnCredentialRepository repository() {
        return repository;
    }

    public boolean isUsableFor(String aUid) {
        return FileCredentialRepository.isValidUid(aUid) && !repository.isFailed();
    }

    // ------------------------------------------------------------------ start

    public Ceremony startLogin(BrowserState aState, String aOrigin) throws WebAuthnException {
        long now = clock.getAsLong();
        PreAuth pre = livePreAuth(aState, now);
        String uid = pre.uid();
        requireUsable(uid);
        EffectivePolicy policy = policy(pre.principal().getGroups(), pre.policyId());
        List<StoredCredential> credentials = eligible(repository.find(uid).orElse(null), policy);
        if (pre.enrolledCredentialId() != null) {
            credentials.removeIf(credential -> !credential.credentialId().equals(pre.enrolledCredentialId()));
        }
        if (credentials.isEmpty()) {
            throw new WebAuthnException("no_eligible_credentials", "No security key registered for this account satisfies the access policy.");
        }
        long expiresAt = Math.min(now + config.getChallengeTtlMillis(), pre.ldapAuthTime() + config.getPreauthTtlMillis());
        Transaction tx = new Transaction(SecureTokens.random(), aState.binding(), Purpose.LOGIN, uid,
                pre.principal().getDisplayName(), pre.principal().getGroups(), pre.preauthId(), pre.ldapAuthTime(), null,
                pre.policyId(), pre.back(), aOrigin, assertionRequest(uid, credentials), null, false, false, null, null,
                false, epoch(uid), now, expiresAt);
        return store(tx);
    }

    public Ceremony startStepUp(BrowserState aState, String aOrigin, String aSessionToken, String aContextId) throws WebAuthnException {
        long now = clock.getAsLong();
        Session session = liveSession(aSessionToken);
        String uid = session.getCanonicalUid();
        requireUsable(uid);
        String policyId = com.payneteasy.nginxauth.policy.PolicySet.NONE_POLICY_ID;
        String back = "/";
        if (aContextId != null && !aContextId.isEmpty()) {
            LoginContext context = contexts.claim(aContextId, aState.binding(), aOrigin)
                    .orElseThrow(() -> new WebAuthnException("invalid_context", "The login link has expired. Open the protected page again."));
            policyId = context.policyId();
            if (context.back() != null) {
                back = context.back();
            }
        }
        EffectivePolicy policy = policy(session.getGroups(), policyId);
        List<StoredCredential> credentials = eligible(repository.find(uid).orElse(null), policy);
        if (credentials.isEmpty()) {
            throw new WebAuthnException("no_eligible_credentials", "No security key registered for this account satisfies the access policy.");
        }
        Transaction tx = new Transaction(SecureTokens.random(), aState.binding(), Purpose.STEP_UP, uid,
                session.getDisplayName(), session.getGroups(), null, session.getLdapAuthTime(), aSessionToken, policyId, back,
                aOrigin, assertionRequest(uid, credentials), null, false, false, null, null, false, epoch(uid), now,
                now + config.getChallengeTtlMillis());
        return store(tx);
    }

    public Ceremony startRegister(BrowserState aState, String aOrigin, String aSessionToken) throws WebAuthnException {
        long now = clock.getAsLong();
        Session session = liveSession(aSessionToken);
        String uid = session.getCanonicalUid();
        requireUsable(uid);
        EffectivePolicy groupPolicy = resolver.resolve(session.getGroups());
        UserRecord record = repository.locks().withLock(uid, () -> ensureRecord(uid));
        if (record.credentials().size() >= MAX_CREDENTIALS) {
            throw new WebAuthnException("too_many_credentials", "Too many security keys. Remove one first.");
        }
        if (record.credentials().isEmpty()) {
            if (groupPolicy.requireWebAuthn()) {
                throw new WebAuthnException("bootstrap_forbidden", "Your account requires a security key. Ask an administrator for an enrollment secret.");
            }
            return store(creationTransaction(Purpose.REGISTER, aState.binding(), aOrigin, uid, session.getDisplayName(),
                    session.getGroups(), null, session.getLdapAuthTime(), aSessionToken, com.payneteasy.nginxauth.policy.PolicySet.NONE_POLICY_ID, "/",
                    groupPolicy, true, null, now + config.getChallengeTtlMillis()));
        }
        List<StoredCredential> credentials = eligible(record, groupPolicy);
        if (credentials.isEmpty()) {
            throw new WebAuthnException("no_eligible_credentials", "None of your security keys satisfies the access policy.");
        }
        Transaction tx = new Transaction(SecureTokens.random(), aState.binding(), Purpose.REGISTER, uid,
                session.getDisplayName(), session.getGroups(), null, session.getLdapAuthTime(), aSessionToken,
                com.payneteasy.nginxauth.policy.PolicySet.NONE_POLICY_ID, "/", aOrigin, assertionRequest(uid, credentials), null, false,
                false, null, null, false, epoch(uid), now, now + config.getChallengeTtlMillis());
        return store(tx);
    }

    public Ceremony startDelete(BrowserState aState, String aOrigin, String aSessionToken, String aCredentialId,
                                boolean aConfirmLast) throws WebAuthnException {
        long now = clock.getAsLong();
        Session session = liveSession(aSessionToken);
        String uid = session.getCanonicalUid();
        requireUsable(uid);
        EffectivePolicy groupPolicy = resolver.resolve(session.getGroups());
        UserRecord record = repository.find(uid).orElseThrow(() -> new WebAuthnException("unknown_credential", "Security key not found."));
        if (aCredentialId == null || record.find(aCredentialId).isEmpty()) {
            throw new WebAuthnException("unknown_credential", "Security key not found.");
        }
        checkLastCredential(record.withoutCredential(aCredentialId), groupPolicy, aConfirmLast);
        List<StoredCredential> credentials = eligible(record, groupPolicy);
        if (credentials.isEmpty()) {
            throw new WebAuthnException("no_eligible_credentials", "None of your security keys satisfies the access policy.");
        }
        Transaction tx = new Transaction(SecureTokens.random(), aState.binding(), Purpose.DELETE_CREDENTIAL, uid,
                session.getDisplayName(), session.getGroups(), null, session.getLdapAuthTime(), aSessionToken,
                com.payneteasy.nginxauth.policy.PolicySet.NONE_POLICY_ID, "/", aOrigin, assertionRequest(uid, credentials), null, false,
                false, null, aCredentialId, aConfirmLast, epoch(uid), now, now + config.getChallengeTtlMillis());
        return store(tx);
    }

    public Ceremony startRecoveryEnroll(BrowserState aState, String aOrigin) throws WebAuthnException {
        long now = clock.getAsLong();
        PreAuth pre = livePreAuth(aState, now);
        if (pre.recoveryGrantId() == null) {
            throw new WebAuthnException("no_recovery_permit", "Enter the enrollment secret first.");
        }
        String uid = pre.uid();
        requireUsable(uid);
        EffectivePolicy policy = policy(pre.principal().getGroups(), pre.policyId());
        repository.locks().withLock(uid, () -> {
            UserRecord record = ensureRecord(uid);
            EnrollmentGrant grant = record.enrollmentGrant();
            if (grant == null || !grant.grantId().equals(pre.recoveryGrantId()) || !grant.isUsable(now)) {
                throw new WebAuthnException("grant_invalid", "The enrollment secret is no longer valid.");
            }
            return record;
        });
        long expiresAt = Math.min(now + config.getChallengeTtlMillis(), pre.ldapAuthTime() + config.getPreauthTtlMillis());
        return store(creationTransaction(Purpose.RECOVERY_ENROLL, aState.binding(), aOrigin, uid, pre.principal().getDisplayName(),
                pre.principal().getGroups(), pre.preauthId(), pre.ldapAuthTime(), null, pre.policyId(), pre.back(), policy, false,
                pre.recoveryGrantId(), expiresAt));
    }

    /**
     * Checks the enrollment secret for the pending pre-authentication. A wrong secret ends the pre-authentication.
     */
    public boolean verifyRecoverySecret(BrowserState aState, String aSecret) throws WebAuthnException {
        long now = clock.getAsLong();
        PreAuth pre = livePreAuth(aState, now);
        String uid = pre.uid();
        requireUsable(uid);
        Optional<UserRecord> record = repository.find(uid);
        EnrollmentGrant grant = record.map(UserRecord::enrollmentGrant).orElse(null);
        boolean ok = grant != null && grant.isUsable(now) && EnrollmentSecrets.matches(aSecret, grant.secretHash());
        if (!ok) {
            states.clearPreAuth(aState, pre.preauthId());
            transactions.cancelForBinding(aState.binding());
            Audit.log("enrollment_secret_rejected", "uid", uid);
            return false;
        }
        states.updatePreAuth(aState, pre.preauthId(), p -> p.withRecoveryGrant(grant.grantId()));
        Audit.log("enrollment_secret_accepted", "uid", uid, "grant", grant.grantId());
        return true;
    }

    // ------------------------------------------------------------------ finish

    public FinishResult finish(BrowserState aState, String aOrigin, String aSessionToken, String aPurpose,
                               String aTransactionId, String aCredentialJson, String aName) throws WebAuthnException {
        Purpose purpose = Purpose.fromWire(aPurpose).orElseThrow(() -> new WebAuthnException("bad_purpose"));
        Transaction tx = transactions.consume(aTransactionId, aState.binding())
                .orElseThrow(() -> new WebAuthnException("unknown_transaction", "This request has expired. Please try again."));
        long now = clock.getAsLong();
        try {
            if (now >= tx.expiresAt()) {
                throw new WebAuthnException("transaction_expired", "This request has expired. Please try again.");
            }
            if (tx.purpose() != purpose) {
                throw new WebAuthnException("purpose_mismatch");
            }
            if (!tx.expectedOrigin().equals(aOrigin)) {
                throw new WebAuthnException("origin_mismatch");
            }
            if (purpose.isPreSession()) {
                PreAuth pre = aState.preAuth();
                if (pre == null || !pre.preauthId().equals(tx.preauthId())) {
                    throw new WebAuthnException("preauth_changed", "Your login has expired. Please enter your password again.");
                }
                if (now - tx.ldapAuthTime() > config.getPreauthTtlMillis()) {
                    throw new WebAuthnException("preauth_expired", "Your login has expired. Please enter your password again.");
                }
            } else {
                if (aSessionToken == null || !aSessionToken.equals(tx.sourceSessionId()) || tokens.peekSession(aSessionToken).isEmpty()) {
                    throw new WebAuthnException("session_gone", "Your session has ended. Please log in again.");
                }
            }
            return tx.isCreation()
                    ? finishRegistration(aState, tx, aCredentialJson, aName)
                    : finishAssertion(aState, tx, aCredentialJson);
        } catch (WebAuthnException e) {
            Audit.log(tx.isCreation() ? "registration_failed" : "authentication_failed",
                    "uid", tx.uid(), "purpose", tx.purpose().wireName(), "reason", e.reason(), "origin", tx.expectedOrigin());
            throw e;
        }
    }

    private FinishResult finishAssertion(BrowserState aState, Transaction aTx, String aJson) throws WebAuthnException {
        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential;
        try {
            credential = PublicKeyCredential.parseAssertionResponseJson(aJson);
        } catch (Exception e) {
            throw new WebAuthnException("malformed_response");
        }
        rejectCrossOrigin(credential.getResponse().getClientDataJSON());

        AssertionResult result;
        try {
            result = relyingParties.get(aTx.expectedOrigin(), false).finishAssertion(FinishAssertionOptions.builder()
                    .request(aTx.assertionRequest())
                    .response(credential)
                    .build());
        } catch (AssertionFailedException | IllegalArgumentException e) {
            throw new WebAuthnException("assertion_invalid");
        }
        if (!result.isSuccess() || !result.isUserVerified() || !aTx.uid().equals(result.getUsername())) {
            throw new WebAuthnException("assertion_invalid");
        }
        String credentialId = result.getCredentialId().getBase64Url();
        boolean receivedBe = result.isBackupEligible();
        boolean receivedBs = result.isBackedUp();
        if (!receivedBe && receivedBs) {
            throw new WebAuthnException("flags_invalid");
        }
        long receivedCount = result.getSignatureCount();
        EffectivePolicy policy = aTx.purpose() == Purpose.LOGIN || aTx.purpose() == Purpose.STEP_UP
                ? policy(aTx.groups(), aTx.policyId())
                : resolver.resolve(aTx.groups());

        return repository.locks().withLock(aTx.uid(), () -> guarded(aState, aTx,
                () -> commitAssertion(aState, aTx, credentialId, receivedBe, receivedBs, receivedCount, result.isUserVerified(), policy)));
    }

    /**
     * Runs a commit under lock(uid) after re-checking, with the current time, everything that may have changed
     * since finish started. Pre-session commits also hold the browser state monitor, so a logout or a new LDAP
     * login in the same browser either happens before (and the commit fails) or after the result is published.
     */
    private <T> T guarded(BrowserState aState, Transaction aTx, UserLocks.Action<T, WebAuthnException> aCommit) throws WebAuthnException {
        beforeCommitHook.run();
        if (!aTx.purpose().isPreSession()) {
            checkCommit(aState, aTx);
            return aCommit.run();
        }
        synchronized (aState) {
            checkCommit(aState, aTx);
            return aCommit.run();
        }
    }

    private void checkCommit(BrowserState aState, Transaction aTx) throws WebAuthnException {
        long now = clock.getAsLong();
        if (now >= aTx.expiresAt()) {
            throw new WebAuthnException("transaction_expired", "This request has expired. Please try again.");
        }
        checkEpoch(aTx);
        if (aTx.purpose().isPreSession()) {
            PreAuth pre = aState.preAuth();
            if (pre == null || !pre.preauthId().equals(aTx.preauthId())) {
                throw new WebAuthnException("preauth_changed", "Your login has expired. Please enter your password again.");
            }
            if (now - aTx.ldapAuthTime() > config.getPreauthTtlMillis()) {
                throw new WebAuthnException("preauth_expired", "Your login has expired. Please enter your password again.");
            }
        }
    }

    private FinishResult commitAssertion(BrowserState aState, Transaction aTx, String aCredentialId, boolean aBe, boolean aBs,
                                         long aCount, boolean aUv, EffectivePolicy aPolicy) throws WebAuthnException {
        String uid = aTx.uid();
        long now = clock.getAsLong();
        UserRecord record = repository.find(uid).orElseThrow(() -> new WebAuthnException("credential_missing"));
        StoredCredential stored = record.find(aCredentialId).orElseThrow(() -> new WebAuthnException("credential_missing"));
        if (stored.backupEligible() != aBe) {
            Audit.log("credential_flags_rejected", "uid", uid, "cred", Audit.cred(aCredentialId), "reason", "be_mismatch");
            throw new WebAuthnException("be_mismatch");
        }
        if (!aPolicy.isEligible(stored.backupEligible(), stored.aaguid())) {
            Audit.log("credential_rejected_by_policy", "uid", uid, "cred", Audit.cred(aCredentialId), "policyId", aTx.policyId());
            throw new WebAuthnException("policy_rejected", "This security key is not allowed by the access policy.");
        }
        long newCount = stored.signCount();
        switch (SignCount.evaluate(stored.signCount(), aCount)) {
            case UPDATE -> newCount = aCount;
            case KEEP -> { }
            case ANOMALY -> {
                Audit.log("signcount_anomaly", "uid", uid, "cred", Audit.cred(aCredentialId),
                        "stored", Long.toString(stored.signCount()), "received", Long.toString(aCount),
                        "policy", config.getCounterPolicy().name().toLowerCase());
                if (config.getCounterPolicy() == WebAuthnConfig.CounterPolicy.REJECT) {
                    throw new WebAuthnException("signcount_anomaly", "This security key reported an invalid signature counter. Contact your administrator.");
                }
            }
        }

        Session source = null;
        if (!aTx.purpose().isPreSession()) {
            source = sourceSession(aTx, record);
        }

        UserRecord updated = record.withCredential(stored.afterUse(newCount, aBs, now));
        if (aTx.purpose() == Purpose.DELETE_CREDENTIAL) {
            if (updated.find(aTx.targetCredentialId()).isEmpty()) {
                throw new WebAuthnException("unknown_credential", "Security key not found.");
            }
            updated = updated.withoutCredential(aTx.targetCredentialId());
            checkLastCredential(updated, resolver.resolve(aTx.groups()), aTx.confirmLast());
        }
        save(updated);

        switch (aTx.purpose()) {
            case LOGIN -> {
                String token = tokens.createSession(Session.withWebAuthn(uid, aTx.displayName(), aTx.groups(), aTx.ldapAuthTime(), now,
                        aCredentialId, aUv, stored.backupEligible()).boundTo(aTx.binding()));
                states.clearPreAuth(aState, aTx.preauthId());
                Audit.log("authentication_succeeded", "uid", uid, "cred", Audit.cred(aCredentialId), "purpose", "login",
                        "policyId", aTx.policyId(), "origin", aTx.expectedOrigin());
                return new SessionIssued(token, aTx.back());
            }
            case STEP_UP -> {
                Session next = Session.withWebAuthn(uid, source.getDisplayName(), source.getGroups(), source.getLdapAuthTime(), now,
                        aCredentialId, aUv, stored.backupEligible()).boundTo(aTx.binding());
                String token = tokens.replaceIfActive(aTx.sourceSessionId(), next)
                        .orElseThrow(() -> new WebAuthnException("session_gone", "Your session has ended. Please log in again."));
                Audit.log("step_up", "uid", uid, "cred", Audit.cred(aCredentialId), "policyId", aTx.policyId(), "origin", aTx.expectedOrigin());
                return new SessionIssued(token, aTx.back());
            }
            case REGISTER -> {
                Audit.log("authentication_succeeded", "uid", uid, "cred", Audit.cred(aCredentialId), "purpose", "register");
                long expiresAt = Math.min(now + config.getChallengeTtlMillis(), now + config.getFreshAuthAgeMillis());
                Transaction create = creationTransaction(Purpose.REGISTER, aTx.binding(), aTx.expectedOrigin(), uid, aTx.displayName(),
                        aTx.groups(), null, aTx.ldapAuthTime(), aTx.sourceSessionId(), aTx.policyId(), aTx.back(),
                        resolver.resolve(aTx.groups()), false, null, expiresAt);
                return new NextCeremony(store(create));
            }
            case DELETE_CREDENTIAL -> {
                tokens.invalidateByCredential(uid, aTx.targetCredentialId());
                Audit.log("credential_removed", "uid", uid, "cred", Audit.cred(aTx.targetCredentialId()),
                        "confirmedWith", Audit.cred(aCredentialId));
                return new Done("Security key removed.");
            }
            default -> throw new WebAuthnException("purpose_mismatch");
        }
    }

    private FinishResult finishRegistration(BrowserState aState, Transaction aTx, String aJson, String aName) throws WebAuthnException {
        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential;
        try {
            credential = PublicKeyCredential.parseRegistrationResponseJson(aJson);
        } catch (Exception e) {
            throw new WebAuthnException("malformed_response");
        }
        rejectCrossOrigin(credential.getResponse().getClientDataJSON());

        RegistrationResult result;
        try {
            result = relyingParties.get(aTx.expectedOrigin(), aTx.attestationDirect()).finishRegistration(FinishRegistrationOptions.builder()
                    .request(aTx.creationOptions())
                    .response(credential)
                    .build());
        } catch (RegistrationFailedException | IllegalArgumentException e) {
            throw new WebAuthnException("registration_invalid");
        }
        if (!result.isUserVerified()) {
            throw new WebAuthnException("registration_invalid");
        }
        boolean be = result.isBackupEligible();
        boolean bs = result.isBackedUp();
        if (!be && bs) {
            throw new WebAuthnException("flags_invalid");
        }
        String aaguid = aaguid(result.getAaguid());
        String credentialId = result.getKeyId().getId().getBase64Url();
        EffectivePolicy policy = aTx.purpose() == Purpose.RECOVERY_ENROLL
                ? policy(aTx.groups(), aTx.policyId())
                : resolver.resolve(aTx.groups());
        if (!policy.isEligible(be, aaguid)) {
            Audit.log("credential_rejected_by_policy", "uid", aTx.uid(), "cred", Audit.cred(credentialId), "aaguid", aaguid,
                    "backupEligible", Boolean.toString(be), "policyId", aTx.policyId());
            throw new WebAuthnException("policy_rejected", "This security key is not allowed by the access policy.");
        }
        List<String> transports = new ArrayList<>();
        for (AuthenticatorTransport transport : credential.getResponse().getTransports()) {
            // the browser value is untrusted: keep only known transports so the stored record stays small
            if (KNOWN_TRANSPORTS.contains(transport.getId()) && !transports.contains(transport.getId())) {
                transports.add(transport.getId());
            }
        }
        long now = clock.getAsLong();
        StoredCredential stored = new StoredCredential(credentialId, result.getPublicKeyCose().getBase64Url(), result.getSignatureCount(),
                aaguid, be, bs, transports, sanitizeName(aName), now, 0L);
        String expectedHandle = aTx.creationOptions().getUser().getId().getBase64Url();

        repository.locks().withLock(aTx.uid(), () -> guarded(aState, aTx, () -> {
            long commitNow = clock.getAsLong();
            UserRecord record = repository.find(aTx.uid()).orElseThrow(() -> new WebAuthnException("user_missing"));
            if (!record.userHandle().equals(expectedHandle)) {
                throw new WebAuthnException("user_handle_changed");
            }
            if (record.find(credentialId).isPresent()) {
                throw new WebAuthnException("duplicate_credential", "This security key is already registered.");
            }
            if (record.credentials().size() >= MAX_CREDENTIALS) {
                throw new WebAuthnException("too_many_credentials", "Too many security keys. Remove one first.");
            }
            if (aTx.bootstrap() && !record.credentials().isEmpty()) {
                throw new WebAuthnException("bootstrap_lost", "A security key was registered meanwhile. Confirm with it to add another one.");
            }
            UserRecord updated = record;
            if (aTx.purpose() == Purpose.RECOVERY_ENROLL) {
                PreAuth pre = aState.preAuth();
                if (pre == null || !aTx.grantId().equals(pre.recoveryGrantId())) {
                    throw new WebAuthnException("preauth_changed", "Your login has expired. Please enter your password again.");
                }
                EnrollmentGrant grant = record.enrollmentGrant();
                if (grant == null || !grant.grantId().equals(aTx.grantId()) || !grant.isUsable(commitNow)) {
                    throw new WebAuthnException("grant_invalid", "The enrollment secret is no longer valid.");
                }
                EnrollmentGrant used = grant.used();
                updated = updated.withGrant(used.usesLeft() > 0 ? used : null);
            } else {
                sourceSession(aTx, record);
            }
            updated = updated.withCredential(stored);
            save(updated);
            Audit.log("credential_registered", "uid", aTx.uid(), "cred", Audit.cred(credentialId), "aaguid", aaguid,
                    "backupEligible", Boolean.toString(be), "purpose", aTx.purpose().wireName(), "origin", aTx.expectedOrigin());
            if (aTx.purpose() == Purpose.RECOVERY_ENROLL) {
                Audit.log("enrollment_grant_used", "uid", aTx.uid(), "grant", aTx.grantId());
                states.updatePreAuth(aState, aTx.preauthId(), p -> p.withEnrolledCredential(credentialId));
            }
            return null;
        }));

        if (aTx.purpose() == Purpose.RECOVERY_ENROLL) {
            return new NextCeremony(startLogin(aState, aTx.expectedOrigin()));
        }
        return new Done("Security key registered.");
    }

    // ------------------------------------------------------------------ logout

    /**
     * Ends everything this browser holds: the session from its cookie, every session issued in this browser
     * binding (a login or step-up that finished concurrently may have published one the cookie does not show
     * yet), the pending pre-authentication and transaction. Takes the same locks in the same order as a commit
     * (lock(uid), then the browser state monitor), so an in-flight finish either fails or is revoked here.
     */
    public void logout(BrowserState aState, String aSessionToken) {
        Optional<Session> session = tokens.peekSession(aSessionToken);
        Runnable revoke = () -> {
            synchronized (aState) {
                tokens.invalidateToken(aSessionToken);
                tokens.invalidateByBrowserBinding(aState.binding());
                states.clearPreAuth(aState, null);
                transactions.cancelForBinding(aState.binding());
            }
        };
        if (session.isPresent()) {
            repository.locks().withLock(session.get().getCanonicalUid(), () -> {
                revoke.run();
                return null;
            });
        } else {
            revoke.run();
        }
        Audit.log("logout", "uid", session.map(Session::getCanonicalUid).orElse(null));
    }

    /** Revokes every session of the user, e.g. after a password change. */
    public void revokeSessions(String aUid) {
        repository.locks().withLock(aUid, () -> {
            tokens.invalidateUser(aUid);
            return null;
        });
        Audit.log("sessions_revoked", "uid", aUid, "reason", "password_changed");
    }

    // ------------------------------------------------------------------ admin

    public record GrantSpec(long ttlHours, int uses, String issuedBy) {
    }

    /**
     * Deletes all credentials (the user handle is kept), revokes the old grant, sessions, transactions and
     * pre-authentications, optionally issues a new grant. Returns the new secret, shown once.
     */
    public Optional<String> adminReset(String aUid, GrantSpec aGrant) throws WebAuthnException {
        requireUsable(aUid);
        return repository.locks().withLock(aUid, () -> {
            Optional<UserRecord> existing = repository.find(aUid);
            String secret = null;
            if (existing.isPresent() || aGrant != null) {
                UserRecord record = existing.isPresent() ? existing.get() : ensureRecord(aUid);
                EnrollmentGrant grant = null;
                if (aGrant != null) {
                    secret = EnrollmentSecrets.generate();
                    grant = newGrant(secret, aGrant);
                }
                save(record.withoutCredentials().withGrant(grant));
                for (StoredCredential credential : record.credentials()) {
                    Audit.log("credential_removed", "uid", aUid, "cred", Audit.cred(credential.credentialId()), "by", "admin_reset");
                }
                if (grant != null) {
                    Audit.log("enrollment_grant_issued", "uid", aUid, "grant", grant.grantId(), "issuedBy", aGrant.issuedBy(),
                            "uses", Integer.toString(grant.usesLeft()), "ttlHours", Long.toString(aGrant.ttlHours()));
                }
            }
            resetEpochs.merge(aUid, 1L, Long::sum);
            tokens.invalidateUser(aUid);
            transactions.cancelForUser(aUid);
            states.clearPreAuthForUser(aUid);
            Audit.log("reset", "uid", aUid, "grant", Boolean.toString(aGrant != null), "issuedBy", aGrant == null ? null : aGrant.issuedBy());
            return Optional.ofNullable(secret);
        });
    }

    public String adminIssueGrant(String aUid, GrantSpec aGrant) throws WebAuthnException {
        requireUsable(aUid);
        return repository.locks().withLock(aUid, () -> {
            UserRecord record = ensureRecord(aUid);
            String secret = EnrollmentSecrets.generate();
            EnrollmentGrant grant = newGrant(secret, aGrant);
            save(record.withGrant(grant));
            Audit.log("enrollment_grant_issued", "uid", aUid, "grant", grant.grantId(), "issuedBy", aGrant.issuedBy(),
                    "uses", Integer.toString(grant.usesLeft()), "ttlHours", Long.toString(aGrant.ttlHours()));
            return secret;
        });
    }

    private EnrollmentGrant newGrant(String aSecret, GrantSpec aSpec) {
        long now = clock.getAsLong();
        return new EnrollmentGrant(UUID.randomUUID().toString(), EnrollmentSecrets.hash(aSecret), now + aSpec.ttlHours() * 3_600_000L,
                aSpec.uses(), aSpec.issuedBy(), now);
    }

    // ------------------------------------------------------------------ helpers

    private Ceremony store(Transaction aTx) throws WebAuthnException {
        if (!transactions.put(aTx)) {
            throw new WebAuthnException("busy", "Service busy. Please try again later.");
        }
        try {
            if (aTx.isCreation()) {
                return new Ceremony(aTx.transactionId(), "create", aTx.creationOptions().toCredentialsCreateJson());
            }
            return new Ceremony(aTx.transactionId(), "get", aTx.assertionRequest().toCredentialsGetJson());
        } catch (Exception e) {
            transactions.consume(aTx.transactionId(), aTx.binding());
            LOG.error("Can't serialize WebAuthn options");
            throw new WebAuthnException("internal");
        }
    }

    private Transaction creationTransaction(Purpose aPurpose, String aBinding, String aOrigin, String aUid, String aDisplayName,
                                            List<String> aGroups, String aPreauthId, long aLdapAuthTime, String aSourceSessionId,
                                            String aPolicyId, String aBack, EffectivePolicy aPolicy, boolean aBootstrap,
                                            String aGrantId, long aExpiresAt) throws WebAuthnException {
        UserRecord record = repository.find(aUid).orElseThrow(() -> new WebAuthnException("user_missing"));
        boolean direct = aPolicy.allowedAaguids() != null;
        PublicKeyCredentialCreationOptions options = relyingParties.get(aOrigin, direct).startRegistration(StartRegistrationOptions.builder()
                .user(UserIdentity.builder()
                        .name(aUid)
                        .displayName(aDisplayName)
                        .id(YubicoRepositoryAdapter.bytes(record.userHandle()))
                        .build())
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                        .residentKey(ResidentKeyRequirement.REQUIRED)
                        .userVerification(UserVerificationRequirement.REQUIRED)
                        .build())
                .timeout(config.getChallengeTtlMillis())
                .build());
        long now = clock.getAsLong();
        return new Transaction(SecureTokens.random(), aBinding, aPurpose, aUid, aDisplayName, aGroups, aPreauthId, aLdapAuthTime,
                aSourceSessionId, aPolicyId, aBack, aOrigin, null, options, direct, aBootstrap, aGrantId, null, false, epoch(aUid),
                now, aExpiresAt);
    }

    private AssertionRequest assertionRequest(String aUid, List<StoredCredential> aCredentials) {
        List<PublicKeyCredentialDescriptor> allow = new ArrayList<>();
        for (StoredCredential credential : aCredentials) {
            allow.add(YubicoRepositoryAdapter.descriptor(credential));
        }
        if (allow.isEmpty()) {
            // an empty allowCredentials would permit any discoverable credential
            throw new IllegalStateException("allowCredentials must not be empty");
        }
        PublicKeyCredentialRequestOptions options = PublicKeyCredentialRequestOptions.builder()
                .challenge(new ByteArray(SecureTokens.randomBytes(32)))
                .rpId(config.getRpId())
                .allowCredentials(allow)
                .userVerification(UserVerificationRequirement.REQUIRED)
                .timeout(config.getChallengeTtlMillis())
                .build();
        return AssertionRequest.builder()
                .publicKeyCredentialRequestOptions(options)
                .username(aUid)
                .build();
    }

    /** Must be called under lock(uid). */
    private UserRecord ensureRecord(String aUid) throws WebAuthnException {
        Optional<UserRecord> existing = repository.find(aUid);
        if (existing.isPresent()) {
            return existing.get();
        }
        UserRecord record = UserRecord.empty(aUid, SecureTokens.random(USER_HANDLE_BYTES));
        save(record);
        return record;
    }

    private void save(UserRecord aRecord) throws WebAuthnException {
        try {
            repository.save(aRecord);
        } catch (DuplicateCredentialException e) {
            throw new WebAuthnException("duplicate_credential", "This security key is already registered.");
        } catch (StorageException e) {
            LOG.error("Can't save WebAuthn credentials: {}", e.getMessage());
            throw new WebAuthnException("storage_error", "Internal error. Please try again later.");
        }
    }

    /** Re-checks the session a session-based ceremony started from. Under lock(uid). */
    private Session sourceSession(Transaction aTx, UserRecord aRecord) throws WebAuthnException {
        Session session = tokens.peekSession(aTx.sourceSessionId())
                .orElseThrow(() -> new WebAuthnException("session_gone", "Your session has ended. Please log in again."));
        if (!session.getCanonicalUid().equals(aTx.uid())) {
            throw new WebAuthnException("session_gone");
        }
        if (session.getMethod() == AuthenticationMethod.LDAP_WEBAUTHN && aRecord.find(session.getCredentialId()).isEmpty()) {
            throw new WebAuthnException("session_gone", "Your session has ended. Please log in again.");
        }
        return session;
    }

    private void checkLastCredential(UserRecord aAfterDeletion, EffectivePolicy aGroupPolicy, boolean aConfirmLast) throws WebAuthnException {
        if (!aAfterDeletion.credentials().isEmpty()) {
            return;
        }
        if (aGroupPolicy.requireWebAuthn()) {
            throw new WebAuthnException("last_credential_required", "Your account requires a security key; the last one can only be removed by an administrator.");
        }
        if (!aConfirmLast) {
            throw new WebAuthnException("confirm_last_required", "This is your last security key. Confirm that you want to remove it.");
        }
    }

    private void checkEpoch(Transaction aTx) throws WebAuthnException {
        if (epoch(aTx.uid()) != aTx.resetEpoch()) {
            throw new WebAuthnException("reset", "Your security keys were reset. Please log in again.");
        }
        if (repository.isFailed()) {
            throw new WebAuthnException("storage_error", "Internal error. Please try again later.");
        }
    }

    private long epoch(String aUid) {
        return resetEpochs.getOrDefault(aUid, 0L);
    }

    private PreAuth livePreAuth(BrowserState aState, long aNow) throws WebAuthnException {
        PreAuth pre = aState.preAuth();
        if (pre == null || !pre.isLive(aNow, config.getPreauthTtlMillis())) {
            throw new WebAuthnException("preauth_expired", "Your login has expired. Please enter your password again.");
        }
        return pre;
    }

    private Session liveSession(String aToken) throws WebAuthnException {
        Session session = tokens.peekSession(aToken)
                .orElseThrow(() -> new WebAuthnException("no_session", "Your session has ended. Please log in again."));
        if (!accessChecker.isSessionCredentialValid(session)) {
            throw new WebAuthnException("no_session", "Your session has ended. Please log in again.");
        }
        return session;
    }

    private void requireUsable(String aUid) throws WebAuthnException {
        if (!FileCredentialRepository.isValidUid(aUid)) {
            throw new WebAuthnException("invalid_uid", "Security keys are not available for this account.");
        }
        if (repository.isFailed()) {
            throw new WebAuthnException("storage_error", "Internal error. Please try again later.");
        }
    }

    private EffectivePolicy policy(List<String> aGroups, String aPolicyId) throws WebAuthnException {
        try {
            EffectivePolicy policy = resolver.resolve(aGroups, aPolicyId);
            if (policy.denyAll()) {
                throw new WebAuthnException("policy_deny", "Access denied by policy.");
            }
            return policy;
        } catch (IllegalArgumentException e) {
            throw new WebAuthnException("unknown_policy", "Access denied by policy.");
        }
    }

    static List<StoredCredential> eligible(UserRecord aRecord, EffectivePolicy aPolicy) {
        List<StoredCredential> list = new ArrayList<>();
        if (aRecord == null) {
            return list;
        }
        for (StoredCredential credential : aRecord.credentials()) {
            if (aPolicy.isEligible(credential.backupEligible(), credential.aaguid())) {
                list.add(credential);
            }
        }
        return list;
    }

    static void rejectCrossOrigin(ByteArray aClientDataJson) throws WebAuthnException {
        JsonObject clientData;
        try {
            JsonElement element = JsonParser.parseString(new String(aClientDataJson.getBytes(), StandardCharsets.UTF_8));
            clientData = element.getAsJsonObject();
        } catch (RuntimeException e) {
            throw new WebAuthnException("malformed_response");
        }
        JsonElement crossOrigin = clientData.get("crossOrigin");
        if (crossOrigin != null && !crossOrigin.isJsonNull()) {
            if (!crossOrigin.isJsonPrimitive() || !crossOrigin.getAsJsonPrimitive().isBoolean() || crossOrigin.getAsBoolean()) {
                throw new WebAuthnException("cross_origin");
            }
        }
        if (clientData.has("topOrigin")) {
            throw new WebAuthnException("cross_origin");
        }
    }

    static String aaguid(ByteArray aAaguid) {
        byte[] bytes = aAaguid.getBytes();
        if (bytes.length != 16) {
            return new UUID(0L, 0L).toString();
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new UUID(buffer.getLong(), buffer.getLong()).toString();
    }

    static String sanitizeName(String aName) {
        if (aName == null) {
            return DEFAULT_NAME;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < aName.length(); i++) {
            char c = aName.charAt(i);
            if (!Character.isISOControl(c)) {
                sb.append(c);
            }
        }
        String name = sb.toString().trim();
        if (name.isEmpty()) {
            return DEFAULT_NAME;
        }
        return name.length() > MAX_NAME_LENGTH ? name.substring(0, MAX_NAME_LENGTH) : name;
    }
}
