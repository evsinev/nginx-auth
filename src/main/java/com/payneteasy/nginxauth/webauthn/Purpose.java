package com.payneteasy.nginxauth.webauthn;

import java.util.Optional;

public enum Purpose {
    LOGIN("login"),
    RECOVERY_ENROLL("recovery_enroll"),
    STEP_UP("step_up"),
    REGISTER("register"),
    DELETE_CREDENTIAL("delete_credential");

    private final String wireName;

    Purpose(String aWireName) {
        wireName = aWireName;
    }

    public String wireName() {
        return wireName;
    }

    public boolean isPreSession() {
        return this == LOGIN || this == RECOVERY_ENROLL;
    }

    public static Optional<Purpose> fromWire(String aValue) {
        for (Purpose purpose : values()) {
            if (purpose.wireName.equals(aValue)) {
                return Optional.of(purpose);
            }
        }
        return Optional.empty();
    }
}
