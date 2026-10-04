package com.payneteasy.nginxauth.servlet;

import com.payneteasy.nginxauth.ldap.GroupNames;
import com.payneteasy.nginxauth.service.Session;
import com.payneteasy.nginxauth.util.SettingsManager;
import com.payneteasy.nginxauth.webauthn.Audit;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Identity of an allowed {@code auth_request} for nginx {@code auth_request_set}: the LDAP uid and the short
 * names of the groups. A value that cannot go into a header safely is dropped, never escaped.
 */
final class IdentityHeaders {

    private static final Logger LOG = LoggerFactory.getLogger(IdentityHeaders.class);

    /** Same as the uid of the credential storage. */
    private static final Pattern UID   = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._@-]{0,127}");
    /** No comma: it separates the groups in the header. */
    private static final Pattern GROUP = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    /** RFC 9110 token. */
    private static final Pattern HEADER_NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");

    private final String userHeader;
    private final String groupsHeader;

    /**
     * @param aUserHeader   empty: the uid is not sent
     * @param aGroupsHeader empty: the groups are not sent
     */
    IdentityHeaders(String aUserHeader, String aGroupsHeader) {
        userHeader = headerName(aUserHeader, "AUTH_REQUEST_USER_HEADER");
        groupsHeader = headerName(aGroupsHeader, "AUTH_REQUEST_GROUPS_HEADER");
    }

    static IdentityHeaders fromSettings() {
        return new IdentityHeaders(SettingsManager.getAuthRequestUserHeader(), SettingsManager.getAuthRequestGroupsHeader());
    }

    private static String headerName(String aValue, String aSetting) {
        if (aValue == null || aValue.isEmpty()) {
            return null;
        }
        if (!HEADER_NAME.matcher(aValue).matches()) {
            throw new IllegalStateException(aSetting + " is not a valid header name");
        }
        return aValue;
    }

    void write(Session aSession, HttpServletResponse aResponse) {
        if (userHeader != null) {
            String uid = aSession.getCanonicalUid();
            if (uid != null && UID.matcher(uid).matches()) {
                aResponse.setHeader(userHeader, uid);
            } else {
                LOG.warn("uid {} cannot be sent in {}, the header is omitted", Audit.clean(uid), userHeader);
            }
        }
        if (groupsHeader != null) {
            String groups = groups(aSession.getGroups());
            if (!groups.isEmpty()) {
                aResponse.setHeader(groupsHeader, groups);
            }
        }
    }

    private String groups(List<String> aGroups) {
        Set<String> names = new LinkedHashSet<>();
        for (String group : aGroups) {
            String name = GroupNames.shortName(group);
            if (name != null && GROUP.matcher(name).matches()) {
                names.add(name);
            } else {
                LOG.warn("Group {} cannot be sent in {}, skipped", Audit.clean(group), groupsHeader);
            }
        }
        return String.join(",", names);
    }
}
