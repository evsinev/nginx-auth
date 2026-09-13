package com.payneteasy.nginxauth.service.impl;

import com.payneteasy.nginxauth.util.SettingsManager;
import org.apache.commons.codec.binary.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.function.LongSupplier;

public class OtpSecretStore {

    private static final Logger LOG = LoggerFactory.getLogger(OtpSecretStore.class);

    private static final long MISSING_MTIME = Long.MIN_VALUE;
    private static final long ERROR_LOG_INTERVAL_MILLIS = 60_000L;

    private final Path file;
    private final long reloadCheckMillis;
    private final LongSupplier clock;
    private final String dummySecret;
    private final boolean fileBacked;

    private volatile Map<String, String> secrets = Collections.emptyMap();
    private boolean loaded;
    private long lastMtime = MISSING_MTIME;
    private long lastCheckAt;
    private long lastErrorLogAt;
    private int loadCount;

    public static OtpSecretStore fromSettings() {
        return new OtpSecretStore(
                Paths.get(SettingsManager.getOtpSecretsFile()),
                5_000L,
                System::currentTimeMillis
        );
    }

    public OtpSecretStore(Path file, long reloadCheckMillis, LongSupplier clock) {
        this.file = file;
        this.reloadCheckMillis = reloadCheckMillis;
        this.clock = clock;
        this.dummySecret = generateDummySecret();
        this.fileBacked = true;
    }

    OtpSecretStore(Map<String, String> secrets, String dummySecret) {
        this.file = null;
        this.reloadCheckMillis = Long.MAX_VALUE;
        this.clock = () -> 0L;
        this.dummySecret = dummySecret;
        this.fileBacked = false;
        this.secrets = Collections.unmodifiableMap(new HashMap<String, String>(secrets));
        this.loaded = true;
    }

    public String getSecret(String username) {
        ensureFresh();
        return secrets.get(username);
    }

    public String dummySecret() {
        return dummySecret;
    }

    int loadCount() {
        return loadCount;
    }

    private void ensureFresh() {
        if (!fileBacked) {
            return;
        }
        long now = clock.getAsLong();
        if (loaded && now - lastCheckAt < reloadCheckMillis) {
            return;
        }
        synchronized (this) {
            now = clock.getAsLong();
            if (loaded && now - lastCheckAt < reloadCheckMillis) {
                return;
            }
            lastCheckAt = now;
            reload();
        }
    }

    private void reload() {
        try {
            if (!Files.isRegularFile(file)) {
                applyMissing();
                return;
            }
            long mtime = Files.getLastModifiedTime(file).toMillis();
            if (loaded && mtime == lastMtime) {
                return;
            }
            Map<String, String> next = new HashMap<String, String>();
            try (InputStream in = Files.newInputStream(file)) {
                Properties properties = new Properties();
                properties.load(in);
                for (String name : properties.stringPropertyNames()) {
                    next.put(name, properties.getProperty(name));
                }
            }
            secrets = Collections.unmodifiableMap(next);
            lastMtime = mtime;
            loaded = true;
            loadCount++;
            LOG.debug("OTP secrets reloaded from {}", file);
        } catch (IOException e) {
            logLoadError("Can't read OTP secrets file", e);
            if (!loaded) {
                secrets = Collections.emptyMap();
                loaded = true;
                loadCount++;
            }
        }
    }

    private void applyMissing() {
        if (!loaded) {
            LOG.error("Can't read OTP secrets file");
            loadCount++;
        } else if (lastMtime != MISSING_MTIME) {
            logLoadError("Can't read OTP secrets file", null);
            loadCount++;
        }
        secrets = Collections.emptyMap();
        lastMtime = MISSING_MTIME;
        loaded = true;
    }

    private void logLoadError(String message, Exception e) {
        long now = clock.getAsLong();
        if (loaded && now - lastErrorLogAt < ERROR_LOG_INTERVAL_MILLIS) {
            return;
        }
        lastErrorLogAt = now;
        if (e != null) {
            LOG.error(message, e);
        } else {
            LOG.error(message);
        }
    }

    private static String generateDummySecret() {
        byte[] bytes = new byte[20];
        new SecureRandom().nextBytes(bytes);
        return new Base32().encodeToString(bytes);
    }
}
