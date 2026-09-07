package com.kokovpn.stealth.server;

/**
 * Trojan-style shared-secret check: a genuine client carries the exact token in the
 * {@code X-Stealth-Auth} header. Anything else — no header, wrong value, or a bare scanner probe —
 * fails and is routed to the fallback, so the proxy stays invisible to active probing.
 *
 * <p>The comparison is constant-time to avoid leaking the token through timing.
 */
final class TokenAuthPolicy implements AuthPolicy {

    static final String AUTH_HEADER = "X-Stealth-Auth";

    private final String expected;

    TokenAuthPolicy(String expected) {
        this.expected = expected == null ? "" : expected;
    }

    @Override
    public boolean verify(HandshakeReader.Head head) {
        if (expected.isEmpty()) {
            // No token configured: accept any well-formed client (dev/local only).
            return true;
        }
        String got = head.header(AUTH_HEADER);
        return got != null && constantTimeEquals(expected, got);
    }

    private static boolean constantTimeEquals(String a, String b) {
        byte[] x = a.getBytes();
        byte[] y = b.getBytes();
        int diff = x.length ^ y.length;
        for (int i = 0; i < x.length && i < y.length; i++) {
            diff |= x[i] ^ y[i];
        }
        return diff == 0;
    }
}
