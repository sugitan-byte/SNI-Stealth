package com.kokovpn.stealth.server;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.util.Collections;

/**
 * Builds the server's TLS listener from a keystore. The server must present a certificate to speak
 * TLS at all; the stealth client deliberately does not validate it (the identity check is the
 * injected token, not the certificate), which is what lets a single IP wear any SNI/front name.
 *
 * <p>JSSE's default behaviour is to RST the connection when the client sends a ClientHello whose
 * SNI does not match any name in the server's certificate (CN or SANs). This is unlike OpenSSL /
 * Stunnel, which complete the handshake and present the certificate regardless. The fix is a
 * permissive {@link SNIMatcher} that matches every hostname — JSSE then skips its own name-check
 * and the TLS handshake always completes, exactly as Stunnel does.
 */
final class TlsContextFactory {

    /**
     * An {@link SNIMatcher} that accepts every SNI value the client sends, regardless of whether
     * it matches the server certificate's CN or any SAN. JSSE consults the matcher registered on
     * {@link SSLParameters} before deciding to alert/RST; returning {@code true} here suppresses
     * the mismatch rejection so the handshake always completes.
     *
     * <p>This is the server-side equivalent of OpenSSL's {@code SSL_CTX_set_tlsext_servername_callback}
     * with a no-op handler, or Stunnel's implicit behaviour of ignoring the client's SNI and
     * presenting the configured certificate unconditionally.
     */
    private static final class AcceptAllSniMatcher extends SNIMatcher {
        AcceptAllSniMatcher() {
            // SNIHostName.TYPE == 0; we want to match all SNI types, including future ones.
            // Registering type 0 is sufficient for the universal "host_name" type that every
            // client sends today. JSSE only queries the matcher for types present in this set,
            // and the type we care about is 0 (RFC 6066 HostName).
            super(0);
        }

        @Override
        public boolean matches(SNIServerName serverName) {
            // Accept unconditionally — we don't care what hostname the client claims.
            // Authentication is handled by the X-Stealth-Auth token, not by TLS name binding.
            return true;
        }
    }

    private TlsContextFactory() {
    }

    static ServerSocketFactory serverSocketFactory(ServerConfig cfg) throws Exception {
        char[] pass = cfg.keystorePass == null ? new char[0] : cfg.keystorePass.toCharArray();
        KeyStore ks = KeyStore.getInstance(guessType(cfg.keystorePath));
        InputStream in = new FileInputStream(cfg.keystorePath);
        try {
            ks.load(in, pass);
        } finally {
            in.close();
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pass);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx.getServerSocketFactory();
    }

    /**
     * Enable a broad protocol range so old clients still negotiate, disable client auth,
     * and — critically — install the permissive {@link AcceptAllSniMatcher} so JSSE never
     * rejects a ClientHello whose SNI does not match the server certificate.
     */
    static void tuneServerSocket(SSLServerSocket ss) {
        try {
            ss.setEnabledProtocols(ss.getSupportedProtocols());
        } catch (Exception ignored) {
        }
        ss.setNeedClientAuth(false);
        ss.setWantClientAuth(false);

        // Install the accept-all SNI matcher. Without this, JSSE sends a
        // TLS unrecognized_name alert (or silently RSTs) when the client's
        // SNI does not match the certificate — producing exactly the
        // "Connection reset during handshake" symptom.
        SSLParameters params = ss.getSSLParameters();
        params.setSNIMatchers(Collections.singletonList(new AcceptAllSniMatcher()));
        ss.setSSLParameters(params);
    }

    private static String guessType(String path) {
        String p = path.toLowerCase();
        if (p.endsWith(".p12") || p.endsWith(".pfx")) {
            return "PKCS12";
        }
        return "JKS";
    }
}
