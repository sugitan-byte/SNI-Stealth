package com.kokovpn.stealth.server;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.Socket;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * The "smart listener" per connection. It inspects the incoming bytes:
 * - If TLS handshake record (0x16), wraps in server SSLSocket with Catch-All Blind SNI.
 * - If Plain TCP (HTTP injection / Stage 3 fallback), passes raw stream directly.
 *
 * Then reads the HTTP handshake head, verifies the auth token, and routes:
 * <ul>
 *   <li>verified + X-Stealth-Mux      -> {@link MuxBridge}</li>
 *   <li>verified + WebSocket upgrade  -> {@link WebSocketBridge}</li>
 *   <li>verified + plain injection    -> {@link Socks5Bridge}</li>
 *   <li>unverified / probe            -> the configured {@link FallbackHandler}</li>
 * </ul>
 */
final class ConnectionHandler implements Runnable {

    private static final int HANDSHAKE_TIMEOUT_MS = 10000;
    private static final int DATA_TIMEOUT_MS = 60000;

    private final Socket client;
    private final SSLSocketFactory sslSocketFactory;
    private final AuthPolicy auth;
    private final InboundBridge socks5;
    private final InboundBridge websocket;
    private final InboundBridge mux;
    private final FallbackHandler fallback;

    ConnectionHandler(Socket client, SSLSocketFactory sslSocketFactory, AuthPolicy auth,
                      InboundBridge socks5, InboundBridge websocket, InboundBridge mux, FallbackHandler fallback) {
        this.client = client;
        this.sslSocketFactory = sslSocketFactory;
        this.auth = auth;
        this.socks5 = socks5;
        this.websocket = websocket;
        this.mux = mux;
        this.fallback = fallback;
    }

    @Override
    public void run() {
        Socket effectiveSocket = client;
        try {
            client.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            client.setTcpNoDelay(true);

            InputStream rawIn = client.getInputStream();
            PushbackInputStream pIn = new PushbackInputStream(rawIn, 1);
            int firstByte = pIn.read();
            if (firstByte == -1) {
                close(client);
                return;
            }
            pIn.unread(firstByte);

            InputStream in;
            OutputStream out;

            // Dual-mode protocol detection:
            // 0x16 (22 decimal) is the standard TLS Handshake record ContentType
            if (firstByte == 0x16 && sslSocketFactory != null) {
                SSLSocket ssl = (SSLSocket) sslSocketFactory.createSocket(client, pIn, true);
                ssl.setUseClientMode(false);
                TlsContextFactory.tuneAcceptedSocket(ssl);
                ssl.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
                ssl.startHandshake();

                effectiveSocket = ssl;
                in = ssl.getInputStream();
                out = ssl.getOutputStream();
            } else {
                // Plain TCP / Stage 3 Fallback mode (e.g. GET / POST / CONNECT HTTP injection)
                effectiveSocket = client;
                in = pIn;
                out = client.getOutputStream();
            }

            HandshakeReader.Head head = HandshakeReader.read(in);
            if (head == null) {
                close(effectiveSocket);
                close(client);
                return;
            }

            // Handshake done — switch to data timeout for the relay phase.
            effectiveSocket.setSoTimeout(DATA_TIMEOUT_MS);

            boolean ok = auth.verify(head);
            if (!ok) {
                String peer = client.getInetAddress() == null ? "?" : client.getInetAddress().getHostAddress();
                System.out.println("[stealth] probe from " + peer + " -> fallback (req=\""
                        + head.requestLine + "\")");
            }
            if (ok) {
                InboundBridge bridge;
                if (head.isMux()) {
                    bridge = mux;               // one connection, many multiplexed SOCKS5 streams
                } else if (head.isWebSocketUpgrade()) {
                    bridge = websocket;
                } else {
                    bridge = socks5;
                }
                bridge.handle(effectiveSocket, in, out, head);
            } else {
                fallback.handle(effectiveSocket, in, out, head);
            }
        } catch (Exception e) {
            String peer = client.getInetAddress() == null ? "?" : client.getInetAddress().getHostAddress();
            System.err.println("[stealth] TLS/conn error from " + peer + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
            if (e.getCause() != null) {
                System.err.println("   caused by: " + e.getCause().getClass().getSimpleName() + ": " + e.getCause().getMessage());
            }
            close(effectiveSocket);
            close(client);
        }
    }

    private void close(Socket s) {
        try {
            if (s != null) {
                s.close();
            }
        } catch (Exception ignored) {
        }
    }
}
