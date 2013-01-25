package com.payneteasy.nginxauth.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

import static com.payneteasy.nginxauth.util.SettingsManager.Setting.*;

/**
 *
 */
public class SettingsManager {

    private static final Logger LOG = LoggerFactory.getLogger(SettingsManager.class);

    enum Setting {
        TOKEN_COOKIE_NAME("AUTH_TOKEN")
        , BACK_URL_NAME("back")
        , AUTH_URL("/auth")
        , INTERNAL_PREFIX("/internal-")
        , X_ACCEL_REDIRECT("X-Accel-Redirect")
        , CONNECTOR_PORT("9091")
        , LDAP_URL("ldaps://localhost:636")
        , LDAP_USERS_DN("ou=users,dc=example,dc=com")
        ;

        private Setting(String aDefaultValue) {
            defaultValue = aDefaultValue;
        }
        private final String defaultValue;
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
            LOG.info(String.format("    %"+max+"s : %s", setting.name(), get(setting)));
        }

        String trustStoreFilename = System.getProperty("javax.net.ssl.trustStore");
        if(trustStoreFilename!=null) {
            File file = new File(trustStoreFilename);
            LOG.info("    javax.net.ssl.trustStore = {}, {}", trustStoreFilename, file.exists()? "exists" : "not exists");

        }
    }

    public static int getConnectorPort() {
        return Integer.parseInt(get(CONNECTOR_PORT));
    }

    public static String getTokenCookieName() {
        return get(TOKEN_COOKIE_NAME);
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

    private static String get(Setting aSetting) {
        return  System.getProperty(aSetting.name(), aSetting.defaultValue);
    }

}
