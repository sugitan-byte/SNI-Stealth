package com.kokovpn.stealth.server;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

/**
 * Minimal RFC 6455 data-frame codec (server side). Writes unmasked binary frames, reads the masked
 * frames a client sends, answers pings, and returns {@code null} on close/EOF. Continuation frames
 * are treated as data — sufficient for relaying an opaque byte stream.
 */
final class WebSocketFrame {

    private static final SecureRandom RANDOM = new SecureRandom();

    private WebSocketFrame() {
    }

    static void writeBinary(OutputStream out, byte[] data, int off, int len, boolean maskOut)
            throws IOException {
        writeFrame(out, 0x2, data, off, len, maskOut);
    }

    private static void writeFrame(OutputStream out, int opcode, byte[] data, int off, int len,
                                   boolean maskOut) throws IOException {
        synchronized (out) {
            out.write(0x80 | (opcode & 0x0f));
            int maskBit = maskOut ? 0x80 : 0x00;
            if (len < 126) {
                out.write(maskBit | len);
            } else if (len < 65536) {
                out.write(maskBit | 126);
                out.write((len >> 8) & 0xff);
                out.write(len & 0xff);
            } else {
                out.write(maskBit | 127);
                for (int i = 7; i >= 0; i--) {
                    out.write((int) (((long) len >> (i * 8)) & 0xff));
                }
            }
            if (maskOut) {
                byte[] key = new byte[4];
                RANDOM.nextBytes(key);
                out.write(key);
                byte[] masked = new byte[len];
                for (int i = 0; i < len; i++) {
                    masked[i] = (byte) (data[off + i] ^ key[i & 3]);
                }
                out.write(masked);
            } else {
                out.write(data, off, len);
            }
            out.flush();
        }
    }

    static byte[] readMessage(InputStream in, OutputStream out, boolean maskOut) throws IOException {
        while (true) {
            int b1 = in.read();
            if (b1 < 0) {
                return null;
            }
            int opcode = b1 & 0x0f;
            int b2 = readByte(in);
            boolean masked = (b2 & 0x80) != 0;
            long len = b2 & 0x7f;
            if (len == 126) {
                len = (readByte(in) << 8) | readByte(in);
            } else if (len == 127) {
                len = 0;
                for (int i = 0; i < 8; i++) {
                    len = (len << 8) | readByte(in);
                }
            }
            byte[] key = null;
            if (masked) {
                key = readN(in, 4);
            }
            byte[] payload = readN(in, (int) len);
            if (masked) {
                for (int i = 0; i < payload.length; i++) {
                    payload[i] ^= key[i & 3];
                }
            }
            switch (opcode) {
                case 0x8:
                    return null;
                case 0x9:
                    writeFrame(out, 0xA, payload, 0, payload.length, maskOut);
                    break;
                case 0xA:
                    break;
                default:
                    return payload;
            }
        }
    }

    private static int readByte(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) {
            throw new EOFException();
        }
        return b;
    }

    private static byte[] readN(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int read = 0;
        while (read < n) {
            int r = in.read(buf, read, n - read);
            if (r < 0) {
                throw new EOFException();
            }
            read += r;
        }
        return buf;
    }
}
