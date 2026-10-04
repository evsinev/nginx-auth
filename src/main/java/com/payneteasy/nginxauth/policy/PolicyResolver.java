package com.payneteasy.nginxauth.policy;

import com.payneteasy.nginxauth.ldap.GroupNames;

import javax.naming.ldap.LdapName;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Builds the effective policy from the user's LDAP groups and the location {@code policyId}.
 */
public final class PolicyResolver {

    private final PolicySet policies;

    public PolicyResolver(PolicySet aPolicies) {
        policies = aPolicies;
    }

    public boolean locationPoliciesEnabled() {
        return policies.locationPoliciesEnabled();
    }

    /**
     * A policyId from nginx is known when it is "none" or a configured location. Without location policies
     * every value is accepted and ignored.
     */
    public boolean isKnownPolicyId(String aPolicyId) {
        if (!policies.locationPoliciesEnabled()) {
            return true;
        }
        if (aPolicyId == null || aPolicyId.isEmpty()) {
            return false;
        }
        return PolicySet.NONE_POLICY_ID.equals(aPolicyId) || policies.locations().containsKey(aPolicyId);
    }

    /**
     * Group-level policy only (no location).
     */
    public EffectivePolicy resolve(List<String> aGroups) {
        return resolve(aGroups, PolicySet.NONE_POLICY_ID);
    }

    /**
     * @throws IllegalArgumentException for an unknown policyId while location policies are enabled
     */
    public EffectivePolicy resolve(List<String> aGroups, String aPolicyId) {
        List<PolicyRule> rules = new ArrayList<>();
        for (Map.Entry<String, PolicyRule> entry : policies.groups().entrySet()) {
            if (memberOf(aGroups, entry.getKey())) {
                rules.add(entry.getValue());
            }
        }
        String policyId = aPolicyId == null ? PolicySet.NONE_POLICY_ID : aPolicyId;
        if (policies.locationPoliciesEnabled() && !PolicySet.NONE_POLICY_ID.equals(policyId)) {
            PolicyRule location = policies.locations().get(policyId);
            if (location == null) {
                throw new IllegalArgumentException("Unknown policyId");
            }
            rules.add(location);
        }
        return EffectivePolicy.combine(rules);
    }

    static boolean memberOf(List<String> aGroups, String aPolicyGroup) {
        LdapName policyDn = GroupNames.parseDn(aPolicyGroup);
        for (String group : aGroups) {
            if (group.equalsIgnoreCase(aPolicyGroup)) {
                return true;
            }
            LdapName groupDn = GroupNames.parseDn(group);
            if (groupDn == null) {
                continue;
            }
            if (policyDn != null && policyDn.size() > 1 && policyDn.equals(groupDn)) {
                return true;
            }
            String cn = GroupNames.leftmostCn(groupDn);
            if (cn != null && cn.equalsIgnoreCase(aPolicyGroup)) {
                return true;
            }
        }
        return false;
    }
}
