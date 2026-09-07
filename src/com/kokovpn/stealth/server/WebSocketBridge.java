package com.kokovpn.stealth.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Completes an RFC 6455 handshake for a verified client, then treats the WebSocket binary frames as
 * an opaque byte stream and runs the same {@link Socks5Bridge} core over it. This is what lets the
 * protocol pass through infrastructure that only forwards WebSocket (CDNs, {@code nginx} locations)
 * while still terminating in an ordinary SOCKS5 proxy.
 */
final class WebSocketBridge implements InboundBridge {

    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    @Override
    public void handle(Socket client, InputStream in, OutputStream out, HandshakeReader.Head head)
            throws Exception {
        String key = head.header("sec-websocket-key");
        if (key == null) {
            // Not a real WebSocket client; nothing to upgrade.
            client.close();
            return;
        }
        String accept = accept(key);
        StringBuilder resp = new StringBuilder();
        resp.append("HTTP/1.1 101 Switching Protocols\r\n");
        resp.append("Upgrade: websocket\r\n");
        resp.append("Connection: Upgrade\r\n");
        resp.append("Sec-WebSocket-Accept: ").append(accept).append("\r\n");
        resp.append("\r\n");
        out.write(resp.toString().getBytes("ISO-8859-1"));
        out.flush();

        InputStream wsIn = new WsInputStream(in, out);
        OutputStream wsOut = new WsOutputStream(out);
        final Socket c = client;
        Socks5Bridge.run(wsIn, wsOut, new Runnable() {
            public void run() {
                try {
                    c.close();
                } catch (IOException ignored) {
                }
            }
        });
    }

    private static String accept(String key) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] digest = sha1.digest((key + GUID).getBytes("US-ASCII"));
        return Base64.getEncoder().encodeToString(digest);
    }

    /** Presents WebSocket data frames from the client as a plain byte stream. */
    private static final class WsInputStream extends InputStream {
        private final InputStream raw;
        private final OutputStream rawOut; // needed to answer pings
        private byte[] buf = new byte[0];
        private int pos = 0;

        WsInputStream(InputStream raw, OutputStream rawOut) {
            this.raw = raw;
            this.rawOut = rawOut;
        }

        @Override
        public int read() throws IOException {
            if (!ensure()) {
                return -1;
            }
            return buf[pos++] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (!ensure()) {
                return -1;
            }
            int n = Math.min(len, buf.length - pos);
            System.arraycopy(buf, pos, b, off, n);
            pos += n;
            return n;
        }

        private boolean ensure() throws IOException {
            while (pos >= buf.length) {
                byte[] msg = WebSocketFrame.readMessage(raw, rawOut, false);
                if (msg == null) {
                    return false;
                }
                buf = msg;
                pos = 0;
            }
            return true;
        }
    }

    /** Writes each chunk to the client as one unmasked WebSocket binary frame. */
    private static final class WsOutputStream extends OutputStream {
        private final OutputStream raw;

        WsOutputStream(OutputStream raw) {
            this.raw = raw;
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[]{(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            WebSocketFrame.writeBinary(raw, b, off, len, false);
        }

        @Override
        public void flush() throws IOException {
            raw.flush();
        }
    }
}
