package com.kokovpn.stealth.server;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

/**
 * Builds the server's TLS listener from a keystore. The server must present a certificate to speak
 * TLS at all; the stealth client deliberately does not validate it (the identity check is the
 * injected token, not the certificate), which is what lets a single IP wear any SNI/front name.
 */
final class TlsContextFactory {

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

    /** Enable a broad protocol range so old clients still negotiate. */
    static void tuneServerSocket(SSLServerSocket ss) {
        try {
            ss.setEnabledProtocols(pickProtocols((SSLServerSocketFactory) SSLServerSocketFactory.getDefault(), ss));
        } catch (Exception ignored) {
        }
        ss.setNeedClientAuth(false);
        ss.setWantClientAuth(false);
    }

    private static String[] pickProtocols(SSLServerSocketFactory f, SSLServerSocket ss) {
        return ss.getSupportedProtocols();
    }

    private static String guessType(String path) {
        String p = path.toLowerCase();
        if (p.endsWith(".p12") || p.endsWith(".pfx")) {
            return "PKCS12";
        }
        return "JKS";
    }
}
