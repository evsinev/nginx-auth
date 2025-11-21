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
        , SECURE_COOKIE              ( "true"                       )
        , API_CHECK_ENABLED          ( "false"                      )
        , API_CHECK_TOKENS           ( "", true               )
        ;

        Setting(String aDefaultValue) {
            defaultValue = aDefaultValue;
            secure = false;
        }

        Setting(String defaultValue, boolean secure) {
            this.defaultValue = defaultValue;
            this.secure       = secure;
        }

        private final String  defaultValue;
        private final boolean secure;
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
        }

        {
            String envValue = System.getenv(aSetting.name());
            if (hasText(envValue)) {
                return envValue;
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

    public static boolean getSecureCookie() {
        return getBoolean(SECURE_COOKIE);
    }

    public static boolean isApiCheckEnabled() {
        return getBoolean(API_CHECK_ENABLED);
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
