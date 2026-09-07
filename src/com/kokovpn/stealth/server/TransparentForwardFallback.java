package com.kokovpn.stealth.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Reverse-proxies an unverified peer to a real decoy origin, replaying the exact bytes it already
 * sent so the origin sees the original request. A prober then receives a genuine site's response —
 * the strongest form of probe resistance, since the port really does serve that site.
 */
final class TransparentForwardFallback implements FallbackHandler {

    private static final int CONNECT_TIMEOUT_MS = 10000;

    private final String host;
    private final int port;

    TransparentForwardFallback(String host, int port) {
        this.host = host;
        this.port = port;
    }

    @Override
    public void handle(Socket client, InputStream in, OutputStream out, HandshakeReader.Head head)
            throws Exception {
        final Socket origin = new Socket();
        try {
            origin.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
        } catch (IOException e) {
            closeQuietly(origin);
            closeQuietly(client);
            return;
        }
        OutputStream originOut = origin.getOutputStream();
        // Replay the request head we already consumed, then stream the rest through untouched.
        if (head != null && head.raw != null) {
            originOut.write(head.raw);
            originOut.flush();
        }
        final Socket c = client;
        final Socket o = origin;
        StreamRelay.pipe(in, originOut, origin.getInputStream(), out, new Runnable() {
            public void run() {
                closeQuietly(o);
                closeQuietly(c);
            }
        });
    }

    private static void closeQuietly(Socket s) {
        try {
            if (s != null) {
                s.close();
            }
        } catch (IOException ignored) {
        }
    }
}
