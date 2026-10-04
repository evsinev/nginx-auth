package com.payneteasy.nginxauth.policy;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Parsed WEBAUTHN_POLICY_FILE. Unknown keys and malformed values are errors.
 */
public final class PolicySet {

    public static final String NONE_POLICY_ID = "none";

    public static final PolicySet EMPTY = new PolicySet(Collections.emptyMap(), Collections.emptyMap());

    private static final Pattern POLICY_ID = Pattern.compile("[A-Za-z0-9_.-]{1,64}");
    private static final Set<String> ROOT_KEYS = Set.of("version", "groups", "locations");
    private static final Set<String> RULE_KEYS = Set.of("requireWebAuthn", "requireSingleDeviceCredential", "allowedAaguids", "maxAuthAge");

    private final Map<String, PolicyRule> groups;
    private final Map<String, PolicyRule> locations;

    PolicySet(Map<String, PolicyRule> groups, Map<String, PolicyRule> locations) {
        this.groups    = Collections.unmodifiableMap(new LinkedHashMap<>(groups));
        this.locations = Collections.unmodifiableMap(new LinkedHashMap<>(locations));
    }

    public static PolicySet load(Path aFile) throws IOException {
        return parse(Files.readString(aFile, StandardCharsets.UTF_8));
    }

    public static PolicySet parse(String aJson) {
        JsonElement rootElement;
        try {
            rootElement = JsonParser.parseString(aJson);
        } catch (JsonParseException e) {
            throw new IllegalArgumentException("Policy file is not valid JSON");
        }
        if (!rootElement.isJsonObject()) {
            throw new IllegalArgumentException("Policy file must be a JSON object");
        }
        JsonObject root = rootElement.getAsJsonObject();
        checkKeys(root, ROOT_KEYS, "policy file");
        JsonElement version = root.get("version");
        if (version == null || !isNumber(version) || version.getAsInt() != 1) {
            throw new IllegalArgumentException("Policy file version must be 1");
        }

        Map<String, PolicyRule> groups = parseRules(root.get("groups"), "groups");
        Map<String, PolicyRule> locations = parseRules(root.get("locations"), "locations");
        for (String id : locations.keySet()) {
            if (!POLICY_ID.matcher(id).matches()) {
                throw new IllegalArgumentException("Invalid location policy id: " + id);
            }
            if (NONE_POLICY_ID.equals(id)) {
                throw new IllegalArgumentException("Location policy id 'none' is reserved");
            }
        }
        return new PolicySet(groups, locations);
    }

    private static Map<String, PolicyRule> parseRules(JsonElement aElement, String aSection) {
        Map<String, PolicyRule> rules = new LinkedHashMap<>();
        if (aElement == null) {
            return rules;
        }
        if (!aElement.isJsonObject()) {
            throw new IllegalArgumentException(aSection + " must be an object");
        }
        for (Map.Entry<String, JsonElement> entry : aElement.getAsJsonObject().entrySet()) {
            String key = entry.getKey().trim();
            if (key.isEmpty()) {
                throw new IllegalArgumentException(aSection + " has an empty key");
            }
            if (!entry.getValue().isJsonObject()) {
                throw new IllegalArgumentException(aSection + "." + key + " must be an object");
            }
            rules.put(key, parseRule(entry.getValue().getAsJsonObject(), aSection + "." + key));
        }
        return rules;
    }

    private static PolicyRule parseRule(JsonObject aRule, String aPath) {
        checkKeys(aRule, RULE_KEYS, aPath);
        boolean requireWebAuthn = parseBoolean(aRule.get("requireWebAuthn"), aPath + ".requireWebAuthn");
        boolean singleDevice    = parseBoolean(aRule.get("requireSingleDeviceCredential"), aPath + ".requireSingleDeviceCredential");

        Set<String> aaguids = null;
        JsonElement aaguidsElement = aRule.get("allowedAaguids");
        if (aaguidsElement != null) {
            if (!aaguidsElement.isJsonArray()) {
                throw new IllegalArgumentException(aPath + ".allowedAaguids must be an array");
            }
            aaguids = new HashSet<>();
            JsonArray array = aaguidsElement.getAsJsonArray();
            for (JsonElement item : array) {
                if (!item.isJsonPrimitive() || !item.getAsJsonPrimitive().isString()) {
                    throw new IllegalArgumentException(aPath + ".allowedAaguids must contain strings");
                }
                aaguids.add(normalizeAaguid(item.getAsString(), aPath));
            }
        }

        Long maxAuthAge = null;
        JsonElement maxAgeElement = aRule.get("maxAuthAge");
        if (maxAgeElement != null) {
            if (!isNumber(maxAgeElement)) {
                throw new IllegalArgumentException(aPath + ".maxAuthAge must be a number of seconds");
            }
            long value = maxAgeElement.getAsLong();
            if (value <= 0 || maxAgeElement.getAsDouble() != value) {
                throw new IllegalArgumentException(aPath + ".maxAuthAge must be a positive integer");
            }
            maxAuthAge = value;
        }
        return new PolicyRule(requireWebAuthn, singleDevice, aaguids, maxAuthAge);
    }

    static String normalizeAaguid(String aValue, String aPath) {
        try {
            return UUID.fromString(aValue.trim()).toString().toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(aPath + ".allowedAaguids has an invalid AAGUID: " + aValue);
        }
    }

    private static boolean parseBoolean(JsonElement aElement, String aPath) {
        if (aElement == null) {
            return false;
        }
        if (!aElement.isJsonPrimitive() || !aElement.getAsJsonPrimitive().isBoolean()) {
            throw new IllegalArgumentException(aPath + " must be true or false");
        }
        return aElement.getAsBoolean();
    }

    private static boolean isNumber(JsonElement aElement) {
        if (!aElement.isJsonPrimitive()) {
            return false;
        }
        JsonPrimitive primitive = aElement.getAsJsonPrimitive();
        return primitive.isNumber();
    }

    private static void checkKeys(JsonObject aObject, Set<String> aAllowed, String aPath) {
        for (String key : aObject.keySet()) {
            if (!aAllowed.contains(key)) {
                throw new IllegalArgumentException("Unknown key '" + key + "' in " + aPath);
            }
        }
    }

    public Map<String, PolicyRule> groups() {
        return groups;
    }

    public Map<String, PolicyRule> locations() {
        return locations;
    }

    public boolean locationPoliciesEnabled() {
        return !locations.isEmpty();
    }

    public boolean hasWebAuthnRequirements() {
        return groups.values().stream().anyMatch(PolicyRule::hasWebAuthnRequirement)
                || locations.values().stream().anyMatch(PolicyRule::hasWebAuthnRequirement);
    }
}
