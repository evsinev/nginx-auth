package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * http://thegreyblog.blogspot.ru/2011/12/google-authenticator-using-it-in-your.html
 *
 */
public class OneTimePasswordServiceImpl implements IOneTimePasswordService {
    private static final Logger LOG = LoggerFactory.getLogger(OneTimePasswordServiceImpl.class);

    private static final long REPLAY_TTL_MILLIS = 120_000L;

    private static final OneTimePasswordServiceImpl INSTANCE = new OneTimePasswordServiceImpl();

    public static OneTimePasswordServiceImpl getInstance() {
        return INSTANCE;
    }

    private OneTimePasswordServiceImpl() {
        this(OtpSecretStore.fromSettings(), System::currentTimeMillis, new GoogleAuthenticator());
    }

    OneTimePasswordServiceImpl(OtpSecretStore store, LongSupplier clock, GoogleAuthenticator googleAuthenticator) {
        this.store = store;
        this.clock = clock;
        this.theGoogleAuthenticator = googleAuthenticator;
        theGoogleAuthenticator.setWindowSize(1);
    }

    @Override
    public boolean checkCode(String aUsername, long aCode) {
        String secret = store.getSecret(aUsername);
        boolean known = secret != null;
        if (!known) {
            secret = store.dummySecret();
        }

        long now = clock.getAsLong();
        purgeExpiredReplays(now);

        boolean ok = theGoogleAuthenticator.check_code(secret, aCode, now);

        String replayKey = aUsername + ":" + aCode;
        Long expiresAt = usedCodes.get(replayKey);
        boolean replayed = expiresAt != null && expiresAt > now;

        boolean accepted = known && ok && !replayed;
        if (accepted) {
            usedCodes.put(replayKey, now + REPLAY_TTL_MILLIS);
        }
        LOG.debug("OTP {} for user {}", accepted ? "accepted" : "rejected", aUsername);
        return accepted;
    }

    @Override
    public void dummyCheck(long aCode) {
        long now = clock.getAsLong();
        theGoogleAuthenticator.check_code(store.dummySecret(), aCode, now);
    }

    int codeAt(String secret, long timeMsec) {
        return theGoogleAuthenticator.codeAt(secret, timeMsec);
    }

    private void purgeExpiredReplays(long now) {
        usedCodes.entrySet().removeIf(entry -> entry.getValue() <= now);
    }

    private final OtpSecretStore store;
    private final LongSupplier clock;
    private final GoogleAuthenticator theGoogleAuthenticator;
    private final ConcurrentHashMap<String, Long> usedCodes = new ConcurrentHashMap<String, Long>();
}
