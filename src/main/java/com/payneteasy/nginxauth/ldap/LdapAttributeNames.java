package com.payneteasy.nginxauth.ldap;

import com.payneteasy.nginxauth.util.SettingsManager;

public record LdapAttributeNames(String uid, String displayName, String groups) {

    public static LdapAttributeNames fromSettings() {
        return new LdapAttributeNames(
                SettingsManager.getLdapUidAttribute(),
                SettingsManager.getLdapDisplayNameAttribute(),
                SettingsManager.getLdapGroupsAttribute()
        );
    }

    public String[] asArray() {
        return new String[] { uid, displayName, groups };
    }
}
