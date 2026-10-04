package com.payneteasy.nginxauth.webauthn;

import com.payneteasy.nginxauth.policy.PolicySet;
import com.payneteasy.nginxauth.util.SettingsManager;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static com.payneteasy.nginxauth.util.StringUtils.hasText;

/**
 * Validated WebAuthn configuration. Any inconsistency is a startup error.
 */
public final class WebAuthnConfig {

    public enum CounterPolicy { REJECT, WARN }

    static final int MIN_ADMIN_TOKEN_LENGTH = 32;

    private final boolean             enabled;
    private final String              rpId;
    private final String              rpName;
    private final List<AllowedOrigin> allowedOrigins;
    private final Path                storageDir;
    private final long                challengeTtlMillis;
    private final long                preauthTtlMillis;
    private final long                freshAuthAgeMillis;
    private final long                loginContextTtlMillis;
    private final CounterPolicy       counterPolicy;
    private final PolicySet           policies;
    private final String              policyHeader;
    private final String              adminToken;
    private final int                 adminPort;

    private WebAuthnConfig(Builder b) {
        enabled               = b.enabled;
        rpId                  = b.rpId;
        rpName                = b.rpName;
        allowedOrigins        = List.copyOf(b.allowedOrigins);
        storageDir            = b.storageDir;
        challengeTtlMillis    = b.challengeTtlSeconds * 1000L;
        preauthTtlMillis      = b.preauthTtlSeconds * 1000L;
        freshAuthAgeMillis    = b.freshAuthAgeSeconds * 1000L;
        loginContextTtlMillis = b.loginContextTtlSeconds * 1000L;
        counterPolicy         = b.counterPolicy;
        policies              = b.policies;
        policyHeader          = b.policyHeader;
        adminToken            = b.adminToken;
        adminPort             = b.adminPort;
    }

    public static WebAuthnConfig fromSettings() {
        Builder b = new Builder();
        b.enabled = SettingsManager.isWebAuthnEnabled();
        String policyFile = SettingsManager.getWebAuthnPolicyFile();
        if (hasText(policyFile)) {
            try {
                b.policies = PolicySet.load(Paths.get(policyFile.trim()));
            } catch (IOException e) {
                throw new IllegalArgumentException("Can't read WEBAUTHN_POLICY_FILE " + policyFile + ": " + e.getMessage());
            }
        }
        b.rpId                   = SettingsManager.getWebAuthnRpId();
        b.rpName                 = SettingsManager.getWebAuthnRpName();
        b.allowedOrigins         = parseOrigins(SettingsManager.getWebAuthnAllowedOrigins());
        b.storageDir             = Paths.get(SettingsManager.getWebAuthnStorageDir());
        b.challengeTtlSeconds    = positive("WEBAUTHN_CHALLENGE_TTL", SettingsManager.getWebAuthnChallengeTtl());
        b.preauthTtlSeconds      = positive("WEBAUTHN_PREAUTH_TTL", SettingsManager.getWebAuthnPreauthTtl());
        b.freshAuthAgeSeconds    = positive("WEBAUTHN_FRESH_AUTH_AGE", SettingsManager.getWebAuthnFreshAuthAge());
        b.loginContextTtlSeconds = positive("WEBAUTHN_LOGIN_CONTEXT_TTL", SettingsManager.getWebAuthnLoginContextTtl());
        b.counterPolicy          = parseCounterPolicy(SettingsManager.getWebAuthnCounterPolicy());
        b.policyHeader           = SettingsManager.getWebAuthnPolicyHeader();
        b.adminToken             = SettingsManager.getWebAuthnAdminToken();
        b.adminPort              = (int) positive("WEBAUTHN_ADMIN_PORT", SettingsManager.getWebAuthnAdminPort());
        return b.build();
    }

    static List<AllowedOrigin> parseOrigins(String aRaw) {
        List<AllowedOrigin> origins = new ArrayList<>();
        if (!hasText(aRaw)) {
            return origins;
        }
        Set<String> seen = new HashSet<>();
        for (String part : aRaw.split(",")) {
            if (part.trim().isEmpty()) {
                continue;
            }
            AllowedOrigin origin = AllowedOrigin.parse(part);
            if (!seen.add(origin.getOrigin())) {
                throw new IllegalArgumentException("Duplicate origin in WEBAUTHN_ALLOWED_ORIGINS: " + origin);
            }
            origins.add(origin);
        }
        return origins;
    }

    static CounterPolicy parseCounterPolicy(String aRaw) {
        String value = aRaw == null ? "" : aRaw.trim().toLowerCase(Locale.ROOT);
        switch (value) {
            case "reject": return CounterPolicy.REJECT;
            case "warn"  : return CounterPolicy.WARN;
            default      : throw new IllegalArgumentException("WEBAUTHN_COUNTER_POLICY must be reject or warn");
        }
    }

    static long positive(String aName, String aRaw) {
        long value;
        try {
            value = Long.parseLong(aRaw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(aName + " must be a positive integer");
        }
        if (value <= 0) {
            throw new IllegalArgumentException(aName + " must be a positive integer");
        }
        return value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private boolean             enabled;
        private String              rpId                   = "";
        private String              rpName                 = "nginx-auth";
        private List<AllowedOrigin> allowedOrigins         = new ArrayList<>();
        private Path                storageDir             = Paths.get("./webauthn");
        private long                challengeTtlSeconds    = 120;
        private long                preauthTtlSeconds      = 300;
        private long                freshAuthAgeSeconds    = 300;
        private long                loginContextTtlSeconds = 300;
        private CounterPolicy       counterPolicy          = CounterPolicy.REJECT;
        private PolicySet           policies               = PolicySet.EMPTY;
        private String              policyHeader           = "X-Policy-Id";
        private String              adminToken             = "";
        private int                 adminPort              = 9092;

        public Builder enabled(boolean v)                  { enabled = v; return this; }
        public Builder rpId(String v)                      { rpId = v; return this; }
        public Builder rpName(String v)                    { rpName = v; return this; }
        public Builder allowedOrigins(String v)            { allowedOrigins = parseOrigins(v); return this; }
        public Builder storageDir(Path v)                  { storageDir = v; return this; }
        public Builder challengeTtlSeconds(long v)         { challengeTtlSeconds = v; return this; }
        public Builder preauthTtlSeconds(long v)           { preauthTtlSeconds = v; return this; }
        public Builder freshAuthAgeSeconds(long v)         { freshAuthAgeSeconds = v; return this; }
        public Builder loginContextTtlSeconds(long v)      { loginContextTtlSeconds = v; return this; }
        public Builder counterPolicy(CounterPolicy v)      { counterPolicy = v; return this; }
        public Builder policies(PolicySet v)               { policies = v; return this; }
        public Builder policyHeader(String v)              { policyHeader = v; return this; }
        public Builder adminToken(String v)                { adminToken = v; return this; }
        public Builder adminPort(int v)                    { adminPort = v; return this; }

        public WebAuthnConfig build() {
            if (!enabled) {
                if (policies.hasWebAuthnRequirements()) {
                    throw new IllegalArgumentException("WEBAUTHN_POLICY_FILE has WebAuthn requirements but WEBAUTHN_ENABLED=false");
                }
                return new WebAuthnConfig(this);
            }
            if (!hasText(rpId)) {
                throw new IllegalArgumentException("WEBAUTHN_RP_ID is required when WEBAUTHN_ENABLED=true");
            }
            rpId = rpId.trim().toLowerCase(Locale.ROOT);
            if (rpId.contains("/") || rpId.contains(":") || rpId.startsWith(".") || rpId.endsWith(".")) {
                throw new IllegalArgumentException("WEBAUTHN_RP_ID must be a domain name");
            }
            if (allowedOrigins.isEmpty()) {
                throw new IllegalArgumentException("WEBAUTHN_ALLOWED_ORIGINS is required when WEBAUTHN_ENABLED=true");
            }
            for (AllowedOrigin origin : allowedOrigins) {
                if (!origin.isUnderRpId(rpId)) {
                    throw new IllegalArgumentException("Origin " + origin + " is not WEBAUTHN_RP_ID or its subdomain");
                }
            }
            if (!hasText(policyHeader)) {
                throw new IllegalArgumentException("WEBAUTHN_POLICY_HEADER is empty");
            }
            if (hasText(adminToken) && adminToken.trim().length() < MIN_ADMIN_TOKEN_LENGTH) {
                throw new IllegalArgumentException("WEBAUTHN_ADMIN_TOKEN must be at least " + MIN_ADMIN_TOKEN_LENGTH + " characters");
            }
            if (adminPort > 65535) {
                throw new IllegalArgumentException("WEBAUTHN_ADMIN_PORT is out of range");
            }
            return new WebAuthnConfig(this);
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public String getRpId() {
        return rpId;
    }

    public String getRpName() {
        return rpName;
    }

    public List<AllowedOrigin> getAllowedOrigins() {
        return allowedOrigins;
    }

    public Path getStorageDir() {
        return storageDir;
    }

    public long getChallengeTtlMillis() {
        return challengeTtlMillis;
    }

    public long getPreauthTtlMillis() {
        return preauthTtlMillis;
    }

    public long getFreshAuthAgeMillis() {
        return freshAuthAgeMillis;
    }

    public long getLoginContextTtlMillis() {
        return loginContextTtlMillis;
    }

    public CounterPolicy getCounterPolicy() {
        return counterPolicy;
    }

    public PolicySet getPolicies() {
        return policies;
    }

    public String getPolicyHeader() {
        return policyHeader;
    }

    public boolean isAdminEnabled() {
        return hasText(adminToken);
    }

    public String getAdminToken() {
        return adminToken == null ? "" : adminToken.trim();
    }

    public int getAdminPort() {
        return adminPort;
    }
}
