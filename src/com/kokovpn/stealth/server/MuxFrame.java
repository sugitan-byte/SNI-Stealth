package com.kokovpn.stealth.server;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Tiny stream-multiplexing frame codec shared by both ends of a mux connection.
 *
 * <p>One TLS connection carries many logical streams so the phone pays a single TLS handshake
 * instead of one per flow. Each frame is:
 *
 * <pre>
 *   streamId : 4 bytes, big-endian
 *   type     : 1 byte   (OPEN | DATA | CLOSE)
 *   length   : 2 bytes, big-endian (payload length, 0..65535)
 *   payload  : length bytes (DATA only)
 * </pre>
 *
 * Writes synchronize on the shared {@code OutputStream}, so many per-stream writer threads can
 * emit frames onto one connection without interleaving. There is no per-stream window: flow control
 * is the single connection's TCP back-pressure, and a small pool of connections spreads the streams
 * to blunt head-of-line blocking.
 */
final class MuxFrame {

    static final int OPEN = 1;
    static final int DATA = 2;
    static final int CLOSE = 3;
    static final int MAX_PAYLOAD = 65535;

    static final class Frame {
        final int streamId;
        final int type;
        final byte[] payload;
        Frame(int streamId, int type, byte[] payload) {
            this.streamId = streamId;
            this.type = type;
            this.payload = payload;
        }
    }

    private MuxFrame() {
    }

    static void writeOpen(OutputStream out, int id) throws IOException {
        writeFrame(out, id, OPEN, null, 0, 0);
    }

    static void writeClose(OutputStream out, int id) throws IOException {
        writeFrame(out, id, CLOSE, null, 0, 0);
    }

    /** Emit {@code len} bytes as one or more DATA frames (chunked to the 64 KB frame cap). */
    static void writeData(OutputStream out, int id, byte[] b, int off, int len) throws IOException {
        int p = off;
        int remaining = len;
        while (remaining > 0) {
            int n = Math.min(remaining, MAX_PAYLOAD);
            writeFrame(out, id, DATA, b, p, n);
            p += n;
            remaining -= n;
        }
    }

    private static void writeFrame(OutputStream out, int id, int type, byte[] b, int off, int len)
            throws IOException {
        synchronized (out) {
            out.write((id >>> 24) & 0xff);
            out.write((id >>> 16) & 0xff);
            out.write((id >>> 8) & 0xff);
            out.write(id & 0xff);
            out.write(type & 0xff);
            out.write((len >>> 8) & 0xff);
            out.write(len & 0xff);
            if (len > 0) {
                out.write(b, off, len);
            }
            out.flush();
        }
    }

    /** Read the next frame, or {@code null} at end of stream. */
    static Frame read(InputStream in) throws IOException {
        int b0 = in.read();
        if (b0 < 0) {
            return null;
        }
        int id = ((b0 & 0xff) << 24) | (read8(in) << 16) | (read8(in) << 8) | read8(in);
        int type = read8(in);
        int len = (read8(in) << 8) | read8(in);
        byte[] payload = new byte[len];
        int r = 0;
        while (r < len) {
            int k = in.read(payload, r, len - r);
            if (k < 0) {
                throw new EOFException();
            }
            r += k;
        }
        return new Frame(id, type, payload);
    }

    private static int read8(InputStream in) throws IOException {
        int x = in.read();
        if (x < 0) {
            throw new EOFException();
        }
        return x;
    }
}
