package com.payneteasy.nginxauth.webauthn;

public final class SignCount {

    public enum Outcome { UPDATE, KEEP, ANOMALY }

    private SignCount() {
    }

    /**
     * stored == 0 &amp;&amp; received == 0 → KEEP; received &gt; stored → UPDATE; otherwise ANOMALY.
     */
    public static Outcome evaluate(long aStored, long aReceived) {
        if (aStored == 0 && aReceived == 0) {
            return Outcome.KEEP;
        }
        if (aReceived > aStored) {
            return Outcome.UPDATE;
        }
        return Outcome.ANOMALY;
    }
}
