package com.payneteasy.nginxauth.ldap;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * Group values from {@code memberOf}: a DN or, in some directories, a plain name.
 */
public final class GroupNames {

    private GroupNames() {
    }

    /**
     * @return the leftmost {@code cn} of a DN, the value itself if it is not a DN, or {@code null} if the DN is
     *         invalid or does not start with {@code cn}
     */
    public static String shortName(String aGroup) {
        if (aGroup == null) {
            return null;
        }
        if (aGroup.indexOf('=') < 0) {
            return aGroup;
        }
        LdapName dn = parseDn(aGroup);
        return dn == null ? null : leftmostCn(dn);
    }

    public static String leftmostCn(LdapName aDn) {
        if (aDn.size() == 0) {
            return null;
        }
        // LdapName indexes RDNs right to left: the leftmost RDN is the last one
        Rdn rdn = aDn.getRdn(aDn.size() - 1);
        if (!"cn".equalsIgnoreCase(rdn.getType())) {
            return null;
        }
        Object value = rdn.getValue();
        return value == null ? null : value.toString();
    }

    public static LdapName parseDn(String aValue) {
        if (aValue == null || aValue.indexOf('=') < 0) {
            return null;
        }
        try {
            return new LdapName(aValue);
        } catch (InvalidNameException | IllegalArgumentException e) {
            return null;
        }
    }
}
