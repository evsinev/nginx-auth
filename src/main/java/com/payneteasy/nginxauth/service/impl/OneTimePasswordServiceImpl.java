package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.service.IOneTimePasswordService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.LongSupplier;

/**
 * http://thegreyblog.blogspot.ru/2011/12/google-authenticator-using-it-in-your.html
 *
 */
public class OneTimePasswordServiceImpl implements IOneTimePasswordService {
    private static final Logger LOG = LoggerFactory.getLogger(OneTimePasswordServiceImpl.class);

    private static final long REPLAY_TTL_MILLIS = 120_000L;

    public OneTimePasswordServiceImpl() {
        this(OneTimePasswordServiceImpl::loadSecretFromFile, System::currentTimeMillis);
    }

    OneTimePasswordServiceImpl(Function<String, String> secrets, LongSupplier clock) {
        this.secrets = secrets;
        this.clock = clock;
        theGoogleAuthenticator.setWindowSize(1);
    }

    @Override
    public boolean checkCode(String aUsername, long aCode) {
        String secret = secrets.apply(aUsername);
        if (secret == null) {
            LOG.warn("Can't find secret for user {}", aUsername);
            return false;
        }

        long now = clock.getAsLong();
        purgeExpiredReplays(now);

        String replayKey = aUsername + ":" + aCode;
        Long expiresAt = usedCodes.get(replayKey);
        if (expiresAt != null && expiresAt > now) {
            return false;
        }

        boolean ok = theGoogleAuthenticator.check_code(secret, aCode, now);
        if (ok) {
            usedCodes.put(replayKey, now + REPLAY_TTL_MILLIS);
        }
        return ok;
    }

    int codeAt(String secret, long timeMsec) {
        return theGoogleAuthenticator.codeAt(secret, timeMsec);
    }

    private void purgeExpiredReplays(long now) {
        usedCodes.entrySet().removeIf(entry -> entry.getValue() <= now);
    }

    private static String loadSecretFromFile(String username) {
        try {
            FileInputStream in = new FileInputStream("otp.properties");
            try {
                Properties properties = new Properties();
                properties.load(in);
                return properties.getProperty(username);
            } finally {
                in.close();
            }
        } catch (IOException e) {
            LOG.error("Can't read otp.properties");
            return null;
        }
    }

    private final Function<String, String> secrets;
    private final LongSupplier clock;
    private final GoogleAuthenticator theGoogleAuthenticator = new GoogleAuthenticator();
    private final ConcurrentHashMap<String, Long> usedCodes = new ConcurrentHashMap<String, Long>();
}
