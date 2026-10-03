package com.payneteasy.nginxauth.ldap;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Result of a full LDAP authentication. {@code canonicalUid} is read from the directory after bind,
 * never taken from the typed login.
 */
public final class LdapPrincipal {

    private final String       canonicalUid;
    private final String       displayName;
    private final List<String> groups;
    private final long         ldapAuthTime;
    private final String       loginName;

    public LdapPrincipal(String canonicalUid, String displayName, List<String> groups, long ldapAuthTime) {
        this(canonicalUid, displayName, groups, ldapAuthTime, null);
    }

    /**
     * @param loginName the name the user typed, which selects the bind DN; null when unknown
     */
    public LdapPrincipal(String canonicalUid, String displayName, List<String> groups, long ldapAuthTime, String loginName) {
        if (canonicalUid == null || canonicalUid.isEmpty()) {
            throw new IllegalArgumentException("canonicalUid is empty");
        }
        this.canonicalUid = canonicalUid;
        this.displayName  = displayName == null || displayName.isEmpty() ? canonicalUid : displayName;
        this.groups       = groups == null ? Collections.emptyList() : List.copyOf(groups);
        this.ldapAuthTime = ldapAuthTime;
        this.loginName    = loginName;
    }

    public static LdapPrincipal fromAttributes(Attributes aAttributes, LdapAttributeNames aNames, long aNow, String aLoginName) throws NamingException {
        String uid = firstValue(aAttributes.get(aNames.uid()));
        if (uid == null || uid.isEmpty()) {
            throw new NamingException("Attribute " + aNames.uid() + " is missing");
        }
        String displayName = firstValue(aAttributes.get(aNames.displayName()));
        List<String> groups = allValues(aAttributes.get(aNames.groups()));
        return new LdapPrincipal(uid, displayName, groups, aNow, aLoginName);
    }

    private static String firstValue(Attribute aAttribute) throws NamingException {
        if (aAttribute == null || aAttribute.size() == 0) {
            return null;
        }
        Object value = aAttribute.get();
        return value == null ? null : value.toString();
    }

    private static List<String> allValues(Attribute aAttribute) throws NamingException {
        if (aAttribute == null) {
            return Collections.emptyList();
        }
        List<String> values = new ArrayList<>();
        NamingEnumeration<?> all = aAttribute.getAll();
        while (all.hasMore()) {
            Object value = all.next();
            if (value != null) {
                values.add(value.toString());
            }
        }
        return values;
    }

    public String getCanonicalUid() {
        return canonicalUid;
    }

    public String getDisplayName() {
        return displayName;
    }

    public List<String> getGroups() {
        return groups;
    }

    public String getLoginName() {
        return loginName;
    }

    public long getLdapAuthTime() {
        return ldapAuthTime;
    }
}
