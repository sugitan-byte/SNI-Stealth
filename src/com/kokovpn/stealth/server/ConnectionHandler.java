package com.kokovpn.stealth.server;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * The "smart listener" per connection. It reads the handshake, decides whether the peer is a
 * genuine client or a probe, and routes accordingly:
 *
 * <ul>
 *   <li>verified + WebSocket upgrade  -&gt; {@link WebSocketBridge}</li>
 *   <li>verified + plain injection    -&gt; {@link Socks5Bridge}</li>
 *   <li>unverified / probe            -&gt; the configured {@link FallbackHandler}</li>
 * </ul>
 *
 * The bridge is chosen by what the client actually sent (the {@code Upgrade} header), so a single
 * listener serves both transports transparently.
 */
final class ConnectionHandler implements Runnable {

    private static final int READ_TIMEOUT_MS = 60000;

    private final Socket client;
    private final AuthPolicy auth;
    private final InboundBridge socks5;
    private final InboundBridge websocket;
    private final FallbackHandler fallback;

    ConnectionHandler(Socket client, AuthPolicy auth, InboundBridge socks5,
                      InboundBridge websocket, FallbackHandler fallback) {
        this.client = client;
        this.auth = auth;
        this.socks5 = socks5;
        this.websocket = websocket;
        this.fallback = fallback;
    }

    @Override
    public void run() {
        try {
            client.setSoTimeout(READ_TIMEOUT_MS);
            client.setTcpNoDelay(true);
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();

            // Reading the first byte drives the TLS handshake on an SSLSocket; a non-TLS probe
            // throws here and is simply dropped.
            HandshakeReader.Head head = HandshakeReader.read(in);
            if (head == null) {
                close();
                return;
            }

            if (auth.verify(head)) {
                InboundBridge bridge = head.isWebSocketUpgrade() ? websocket : socks5;
                bridge.handle(client, in, out, head);
            } else {
                fallback.handle(client, in, out, head);
            }
        } catch (Exception e) {
            // Probes, TLS errors and resets all land here; nothing actionable, just close.
            close();
        }
    }

    private void close() {
        try {
            client.close();
        } catch (Exception ignored) {
        }
    }
}
