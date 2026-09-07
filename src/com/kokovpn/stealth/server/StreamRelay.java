package com.kokovpn.stealth.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * A pair of one-directional byte pumps between two streams, closing both ends when either side
 * finishes. Used by both bridges and the transparent-forward fallback.
 */
final class StreamRelay {

    private static final int BUF = 16384;

    private StreamRelay() {
    }

    /** Relay a&lt;-&gt;b in both directions on daemon threads; {@code closer} runs once when done. */
    static void pipe(final InputStream aIn, final OutputStream aOut,
                     final InputStream bIn, final OutputStream bOut,
                     final Runnable closer) {
        final java.util.concurrent.atomic.AtomicInteger live = new java.util.concurrent.atomic.AtomicInteger(2);
        Runnable onEnd = new Runnable() {
            public void run() {
                if (live.decrementAndGet() == 0 && closer != null) {
                    closer.run();
                }
            }
        };
        start(aIn, bOut, onEnd);
        start(bIn, aOut, onEnd);
    }

    private static void start(final InputStream in, final OutputStream out, final Runnable onEnd) {
        Thread t = new Thread(new Runnable() {
            public void run() {
                byte[] buffer = new byte[BUF];
                try {
                    int n;
                    while ((n = in.read(buffer)) != -1) {
                        out.write(buffer, 0, n);
                        out.flush();
                    }
                } catch (IOException ignored) {
                } finally {
                    onEnd.run();
                }
            }
        });
        t.setDaemon(true);
        t.start();
    }
}
