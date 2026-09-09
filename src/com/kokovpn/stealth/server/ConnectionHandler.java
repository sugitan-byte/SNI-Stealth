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

    /**
     * Maximum time allowed for the TLS handshake + HTTP head to arrive. Kept short so a
     * carrier-delayed or probe connection does not hold a worker thread for a full minute —
     * which would starve the pool when many non-mux connections arrive simultaneously.
     */
    private static final int HANDSHAKE_TIMEOUT_MS = 10000;

    /**
     * Timeout for the relay phase after the handshake completes. Long enough for the SOCKS5
     * negotiation, outbound connect, and idle periods in a real session.
     */
    private static final int DATA_TIMEOUT_MS = 60000;

    private final Socket client;
    private final AuthPolicy auth;
    private final InboundBridge socks5;
    private final InboundBridge websocket;
    private final InboundBridge mux;
    private final FallbackHandler fallback;

    ConnectionHandler(Socket client, AuthPolicy auth, InboundBridge socks5,
                      InboundBridge websocket, InboundBridge mux, FallbackHandler fallback) {
        this.client = client;
        this.auth = auth;
        this.socks5 = socks5;
        this.websocket = websocket;
        this.mux = mux;
        this.fallback = fallback;
    }

    @Override
    public void run() {
        try {
            // Ensure the permissive SNIMatcher and protocols are applied directly to the
            // accepted SSLSocket instance before the TLS handshake triggers on read().
            TlsContextFactory.tuneAcceptedSocket(client);

            // Short timeout for the TLS+HTTP handshake phase. On SSLSocket the handshake fires
            // on the first read(); this timeout bounds how long a carrier-delayed ClientHello
            // holds a worker thread. After the head is parsed we switch to a longer data timeout.
            client.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
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

            // Handshake done — switch to data timeout for the relay phase.
            client.setSoTimeout(DATA_TIMEOUT_MS);

            boolean ok = auth.verify(head);
            if (!ok) {
                // Only probes are worth a line; a genuine client is silent. Keeps the journal quiet.
                String peer = client.getInetAddress() == null ? "?" : client.getInetAddress().getHostAddress();
                System.out.println("[stealth] probe from " + peer + " -> fallback (req=\""
                        + head.requestLine + "\")");
            }
            if (ok) {
                // Mux is an explicit protocol signal and must win over any Upgrade header — a mux
                // client's injected payload often carries a decoy "Upgrade: websocket" line as DPI
                // camouflage, and routing that to the WebSocket bridge (which then demands a
                // Sec-WebSocket-Key it will never get) closes the connection and makes the client
                // reconnect forever. So: mux first, real WebSocket second, plain SOCKS5 last.
                InboundBridge bridge;
                if (head.isMux()) {
                    bridge = mux;               // one connection, many multiplexed SOCKS5 streams
                } else if (head.isWebSocketUpgrade()) {
                    bridge = websocket;
                } else {
                    bridge = socks5;
                }
                bridge.handle(client, in, out, head);
            } else {
                fallback.handle(client, in, out, head);
            }
        } catch (Exception e) {
            String peer = client.getInetAddress() == null ? "?" : client.getInetAddress().getHostAddress();
            System.err.println("[stealth] TLS/conn error from " + peer + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
            if (e.getCause() != null) {
                System.err.println("   caused by: " + e.getCause().getClass().getSimpleName() + ": " + e.getCause().getMessage());
            }
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
