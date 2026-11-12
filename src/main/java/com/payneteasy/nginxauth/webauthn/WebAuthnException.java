package com.payneteasy.nginxauth.webauthn;

/**
 * Ceremony failure. {@link #reason()} is a stable code for logs and audit; {@link #userMessage()} is shown
 * to the user and never contains library details.
 */
public class WebAuthnException extends Exception {

    private final String reason;
    private final String userMessage;

    public WebAuthnException(String aReason, String aUserMessage) {
        super(aReason, null, false, false);
        reason = aReason;
        userMessage = aUserMessage;
    }

    public WebAuthnException(String aReason) {
        this(aReason, "Security key verification failed. Please try again.");
    }

    public String reason() {
        return reason;
    }

    public String userMessage() {
        return userMessage;
    }
}
