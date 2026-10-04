package com.payneteasy.nginxauth.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

import static com.payneteasy.nginxauth.util.SettingsManager.Setting.*;
import static com.payneteasy.nginxauth.util.StringUtils.hasText;
import static com.payneteasy.nginxauth.util.StringUtils.isEmpty;

/**
 *
 */
public class SettingsManager {

    private static final Logger LOG = LoggerFactory.getLogger(SettingsManager.class);

    enum Setting {
          TOKEN_COOKIE_NAME          ( "AUTH_TOKEN"                 )
        , TOKEN_COOKIE_ASSIGNED_NAME ( "AUTH_TOKEN_ASSIGNED"        )
        , BACK_URL_NAME              ( "back"                       )
        , AUTH_URL                   ( "/auth"                      )
        , INTERNAL_PREFIX            ( "/internal-"                 )
        , X_ACCEL_REDIRECT           ( "X-Accel-Redirect"           )
        , CONNECTOR_PORT             ( "9091"                       )
        , LDAP_URL                   ( "ldaps://localhost:636"      )
        , LDAP_USERS_DN              ( "ou=users,dc=example,dc=com" )
        , OTP_ENABLED                ( "true"                       )
        , OTP_SECRETS_FILE           ( "otp.properties"             )
        , SECURE_COOKIE              ( "true"                       )
        , API_CHECK_ENABLED          ( "false"                      )
        , API_CHECK_TOKENS           ( "", true               )
        , LOGIN_MAX_FAILURES         ( "2"                          )
        , LOGIN_IP_MAX_FAILURES      ( "20"                         )
        , LOGIN_DELAYS_SECONDS       ( "0,2"                        )
        , LOGIN_LOCKOUT_SECONDS      ( "300"                        )
        , LOGIN_FAILURE_WINDOW_SECONDS ( "900"                      )
        , LOGIN_MAX_CONCURRENT_DELAYS ( "32"                        )
        , CLIENT_IP_HEADER           ( "X-Real-IP"                  )
        , LDAP_UID_ATTRIBUTE         ( "uid"                        )
        , LDAP_DISPLAY_NAME_ATTRIBUTE ( "displayName"               )
        , LDAP_GROUPS_ATTRIBUTE      ( "memberOf"                   )
        , WEBAUTHN_ENABLED           ( "false"                      )
        , WEBAUTHN_RP_ID             ( ""                           )
        , WEBAUTHN_RP_NAME           ( "nginx-auth"                 )
        , WEBAUTHN_ALLOWED_ORIGINS   ( ""                           )
        , WEBAUTHN_STORAGE_DIR       ( "./webauthn"                 )
        , WEBAUTHN_CHALLENGE_TTL     ( "120"                        )
        , WEBAUTHN_PREAUTH_TTL       ( "300"                        )
        , WEBAUTHN_FRESH_AUTH_AGE    ( "300"                        )
        , WEBAUTHN_LOGIN_CONTEXT_TTL ( "300"                        )
        , WEBAUTHN_COUNTER_POLICY    ( "reject"                     )
        , WEBAUTHN_POLICY_FILE       ( ""                           )
        , WEBAUTHN_POLICY_HEADER     ( "X-Policy-Id"                )
        , WEBAUTHN_ADMIN_TOKEN       ( "", true                     )
        , WEBAUTHN_ADMIN_PORT        ( "9092"                       )
        , AUTH_REQUEST_USER_HEADER   ( "X-Auth-User"  , false, true )
        , AUTH_REQUEST_GROUPS_HEADER ( "X-Auth-Groups", false, true )
        ;

        Setting(String aDefaultValue) {
            this(aDefaultValue, false);
        }

        Setting(String defaultValue, boolean secure) {
            this(defaultValue, secure, false);
        }

        /**
         * @param emptyAllowed an explicitly set empty value is kept (turns the feature off) instead of
         *                     falling back to the default
         */
        Setting(String defaultValue, boolean secure, boolean emptyAllowed) {
            this.defaultValue = defaultValue;
            this.secure       = secure;
            this.emptyAllowed = emptyAllowed;
        }

        private final String  defaultValue;
        private final boolean secure;
        private final boolean emptyAllowed;
    }

    public static void logCurrentSettings() {
        int max = 0;
        for (Setting setting : Setting.values()) {
            if(setting.name().length()>max) {
                max = setting.name().length();
            }
        }

        LOG.info("Settings:");
        for (Setting setting : Setting.values()) {
            if (setting.secure) {
                LOG.info("{}", String.format("    %"+max+"s : %s", setting.name(), "length=" + get(setting).length()));
            } else {
                LOG.info("{}", String.format("    %"+max+"s : %s", setting.name(), get(setting)));
            }
        }

        String trustStoreFilename = System.getProperty("javax.net.ssl.trustStore");
        if(trustStoreFilename!=null) {
            File file = new File(trustStoreFilename);
            LOG.info("    javax.net.ssl.trustStore = {}, {}", trustStoreFilename, file.exists()? "exists" : "not exists");

        }
    }

    private static String get(Setting aSetting) {
        {
            String propertyValue = System.getProperty(aSetting.name());
            if (hasText(propertyValue)) {
                return propertyValue;
            }
            if (aSetting.emptyAllowed && propertyValue != null) {
                return "";
            }
        }

        {
            String envValue = System.getenv(aSetting.name());
            if (hasText(envValue)) {
                return envValue;
            }
            if (aSetting.emptyAllowed && envValue != null) {
                return "";
            }
        }

        return aSetting.defaultValue;
    }

    private static boolean getBoolean(Setting aSetting) {
        return Boolean.parseBoolean(get(aSetting));
    }

    public static int getConnectorPort() {
        return Integer.parseInt(get(CONNECTOR_PORT));
    }

    public static String getTokenCookieName() {
        return get(TOKEN_COOKIE_NAME);
    }

    public static String getTokenCookieAssignedName() {
        return get(TOKEN_COOKIE_ASSIGNED_NAME);
    }

    public static String getBackUrlName() {
        return get(BACK_URL_NAME);
    }

    public static String getAuthUrl() {
        return get(AUTH_URL);
    }

    public static String getInternalPrefix() {
        return get(INTERNAL_PREFIX);
    }

    public static String getXAccessRedirect() {
        return get(X_ACCEL_REDIRECT);
    }

    public static String getLdapUrl() {
        return get(LDAP_URL);
    }

    public static String getLdapUsersDn() {
        return get(LDAP_USERS_DN);
    }

    public static boolean isOtpEnabled() {
        return getBoolean(OTP_ENABLED);
    }

    public static String getOtpSecretsFile() {
        return get(OTP_SECRETS_FILE);
    }

    public static boolean getSecureCookie() {
        return getBoolean(SECURE_COOKIE);
    }

    public static boolean isApiCheckEnabled() {
        return getBoolean(API_CHECK_ENABLED);
    }

    public static int getLoginMaxFailures() {
        return Integer.parseInt(get(LOGIN_MAX_FAILURES));
    }

    public static int getLoginIpMaxFailures() {
        return Integer.parseInt(get(LOGIN_IP_MAX_FAILURES));
    }

    public static String getLoginDelaysSeconds() {
        return get(LOGIN_DELAYS_SECONDS);
    }

    public static int getLoginLockoutSeconds() {
        return Integer.parseInt(get(LOGIN_LOCKOUT_SECONDS));
    }

    public static int getLoginFailureWindowSeconds() {
        return Integer.parseInt(get(LOGIN_FAILURE_WINDOW_SECONDS));
    }

    public static int getLoginMaxConcurrentDelays() {
        return Integer.parseInt(get(LOGIN_MAX_CONCURRENT_DELAYS));
    }

    public static String getClientIpHeader() {
        return get(CLIENT_IP_HEADER);
    }

    public static String getLdapUidAttribute() {
        return get(LDAP_UID_ATTRIBUTE);
    }

    public static String getLdapDisplayNameAttribute() {
        return get(LDAP_DISPLAY_NAME_ATTRIBUTE);
    }

    public static String getLdapGroupsAttribute() {
        return get(LDAP_GROUPS_ATTRIBUTE);
    }

    public static boolean isWebAuthnEnabled() {
        return getBoolean(WEBAUTHN_ENABLED);
    }

    public static String getWebAuthnRpId() {
        return get(WEBAUTHN_RP_ID);
    }

    public static String getWebAuthnRpName() {
        return get(WEBAUTHN_RP_NAME);
    }

    public static String getWebAuthnAllowedOrigins() {
        return get(WEBAUTHN_ALLOWED_ORIGINS);
    }

    public static String getWebAuthnStorageDir() {
        return get(WEBAUTHN_STORAGE_DIR);
    }

    public static String getWebAuthnChallengeTtl() {
        return get(WEBAUTHN_CHALLENGE_TTL);
    }

    public static String getWebAuthnPreauthTtl() {
        return get(WEBAUTHN_PREAUTH_TTL);
    }

    public static String getWebAuthnFreshAuthAge() {
        return get(WEBAUTHN_FRESH_AUTH_AGE);
    }

    public static String getWebAuthnLoginContextTtl() {
        return get(WEBAUTHN_LOGIN_CONTEXT_TTL);
    }

    public static String getWebAuthnCounterPolicy() {
        return get(WEBAUTHN_COUNTER_POLICY);
    }

    public static String getWebAuthnPolicyFile() {
        return get(WEBAUTHN_POLICY_FILE);
    }

    public static String getWebAuthnPolicyHeader() {
        return get(WEBAUTHN_POLICY_HEADER);
    }

    public static String getWebAuthnAdminToken() {
        return get(WEBAUTHN_ADMIN_TOKEN);
    }

    public static String getWebAuthnAdminPort() {
        return get(WEBAUTHN_ADMIN_PORT);
    }

    public static String getAuthRequestUserHeader() {
        return get(AUTH_REQUEST_USER_HEADER).trim();
    }

    public static String getAuthRequestGroupsHeader() {
        return get(AUTH_REQUEST_GROUPS_HEADER).trim();
    }

    public static Set<String> getAccessTokens() {
        String tokens = get(API_CHECK_TOKENS);
        if (isEmpty(tokens)) {
            return Collections.emptySet();
        }

        StringTokenizer st = new StringTokenizer(tokens, ", ");
        Set<String> result = new HashSet<>();
        while (st.hasMoreTokens()) {
            result.add("Bearer " + st.nextToken());
        }
        return result;
    }

}
