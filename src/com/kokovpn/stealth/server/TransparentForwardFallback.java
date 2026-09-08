package com.kokovpn.stealth.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Reverse-proxies an unverified peer to a real decoy origin, replaying the exact bytes it already
 * sent so the origin sees the original request. A prober then receives a genuine site's response —
 * the strongest form of probe resistance, since the port really does serve that site.
 *
 * <p><b>TLS re-origination.</b> This server terminates TLS, so by the time a connection reaches the
 * fallback the bytes in hand are already <em>decrypted</em> plaintext (an HTTP request). Piping that
 * plaintext straight to a decoy on a TLS port (e.g. {@code decoy.example:443}) would fail — the
 * origin expects a ClientHello, not plaintext. So when {@code tls} is set the fallback opens a fresh
 * TLS session to the origin and replays the plaintext request inside it. Point it at a plaintext
 * origin ({@code :80}) with {@code tls=false} instead, and it forwards the raw bytes directly.
 */
final class TransparentForwardFallback implements FallbackHandler {

    private static final int CONNECT_TIMEOUT_MS = 10000;

    private final String host;
    private final int port;
    private final boolean tls;

    TransparentForwardFallback(String host, int port, boolean tls) {
        this.host = host;
        this.port = port;
        this.tls = tls;
    }

    @Override
    public void handle(Socket client, InputStream in, OutputStream out, HandshakeReader.Head head)
            throws Exception {
        Socket origin = new Socket();
        try {
            origin.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            origin.setTcpNoDelay(true);
            if (tls) {
                origin = wrapTls(origin);   // re-encrypt: the decoy on :443 wants a real TLS session
            }
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
        // Cross-wire client <-> origin: client.in -> origin.out, origin.in -> client.out.
        StreamRelay.pipe(in, out, origin.getInputStream(), originOut, new Runnable() {
            public void run() {
                closeQuietly(o);
                closeQuietly(c);
            }
        });
    }

    /**
     * Layer TLS over an already-connected socket to the origin, with SNI set to the decoy host so a
     * name-based virtual host answers correctly. The origin's certificate is not validated — the
     * fallback is camouflage, not a security boundary, and the decoy may present any cert.
     */
    private Socket wrapTls(Socket plain) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, TRUST_ALL, new SecureRandom());
        SSLSocketFactory f = ctx.getSocketFactory();
        SSLSocket ssl = (SSLSocket) f.createSocket(plain, host, port, true);
        ssl.setUseClientMode(true);
        ssl.setEnabledProtocols(ssl.getSupportedProtocols());
        SSLParameters params = ssl.getSSLParameters();
        try {
            params.setServerNames(Collections.<javax.net.ssl.SNIServerName>singletonList(new SNIHostName(host)));
        } catch (IllegalArgumentException ignored) {
            // host is an IP literal, which cannot be an SNI name — leave SNI unset.
        }
        ssl.setSSLParameters(params);
        ssl.startHandshake();
        return ssl;
    }

    private static final TrustManager[] TRUST_ALL = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
                public void checkClientTrusted(X509Certificate[] c, String a) {
                }
                public void checkServerTrusted(X509Certificate[] c, String a) {
                }
            }
    };

    private static void closeQuietly(Socket s) {
        try {
            if (s != null) {
                s.close();
            }
        } catch (IOException ignored) {
        }
    }
}
