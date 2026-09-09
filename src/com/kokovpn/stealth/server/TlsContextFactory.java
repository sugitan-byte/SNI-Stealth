package com.kokovpn.stealth.server;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

/**
 * Builds the server's TLS listener from a keystore.
 *
 * <p>By default, Java's JSSE enforces strict SNI matching:
 * <ol>
 *   <li>The {@link SNIMatcher} rejects mismatched SNI with an {@code unrecognized_name} TLS alert or connection reset.</li>
 *   <li>Sun's {@code X509KeyManagerImpl} filters keystore aliases by comparing the client's SNI hostname against the certificate's CN and SANs. When no match is found, {@code chooseServerAlias} returns {@code null}, causing JSSE to abort with {@code SSL_HANDSHAKE_FAILURE} (BoringSSL 0x100000d7).</li>
 *   <li>Accepted {@link SSLSocket} instances do not reliably inherit custom {@link SNIMatcher}s from the parent {@link SSLServerSocket} across all JVM versions.</li>
 * </ol>
 *
 * This factory implements a complete "Catch-All" (Blind SNI) TLS server by:
 * <ol>
 *   <li>Wrapping the {@link X509ExtendedKeyManager} in {@link SniBlindKeyManager} to always return the default server certificate alias when SNI does not match.</li>
 *   <li>Registering {@link AcceptAllSniMatcher} on both the {@link SSLServerSocket} and every accepted {@link SSLSocket} instance before the handshake starts.</li>
 * </ol>
 */
final class TlsContextFactory {

    // -----------------------------------------------------------------------------------------
    // AcceptAllSniMatcher
    // -----------------------------------------------------------------------------------------

    /**
     * An {@link SNIMatcher} that accepts every incoming SNI value unconditionally,
     * matching RFC 6066 host_name (type 0) and any other server name type.
     */
    static final class AcceptAllSniMatcher extends SNIMatcher {
        AcceptAllSniMatcher() {
            super(0); // type 0 = RFC 6066 host_name
        }

        @Override
        public boolean matches(SNIServerName serverName) {
            return true;
        }
    }

    // -----------------------------------------------------------------------------------------
    // SniBlindKeyManager
    // -----------------------------------------------------------------------------------------

    /**
     * Wraps the real {@link X509ExtendedKeyManager}. When the default key manager returns
     * {@code null} because the client's SNI does not match any certificate in the keystore,
     * this manager falls back to the default server certificate alias for compatible key types.
     */
    private static final class SniBlindKeyManager extends X509ExtendedKeyManager {

        private final X509ExtendedKeyManager delegate;
        private final String fixedAlias;
        private final String keyAlgorithm;

        SniBlindKeyManager(X509ExtendedKeyManager delegate, String fixedAlias, String keyAlgorithm) {
            this.delegate = delegate;
            this.fixedAlias = fixedAlias;
            this.keyAlgorithm = keyAlgorithm != null ? keyAlgorithm.toUpperCase() : "RSA";
        }

        private boolean isCompatible(String keyType) {
            if (keyType == null || keyType.isEmpty()) {
                return true;
            }
            String kt = keyType.toUpperCase();
            if ("RSA".equals(keyAlgorithm)) {
                return kt.contains("RSA") || "NONE".equals(kt);
            } else if ("EC".equals(keyAlgorithm)) {
                return kt.contains("EC") || "ECDSA".equals(kt);
            }
            return kt.contains(keyAlgorithm);
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            // First check if the delegate can find a matching alias
            String alias = delegate.chooseServerAlias(keyType, issuers, socket);
            if (alias != null) {
                return alias;
            }
            // Fall back to the default certificate if key type is compatible
            if (isCompatible(keyType)) {
                return fixedAlias;
            }
            return null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            String alias = delegate.chooseEngineServerAlias(keyType, issuers, engine);
            if (alias != null) {
                return alias;
            }
            if (isCompatible(keyType)) {
                return fixedAlias;
            }
            return null;
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            String[] aliases = delegate.getServerAliases(keyType, issuers);
            if (aliases != null && aliases.length > 0) {
                return aliases;
            }
            if (isCompatible(keyType)) {
                return new String[]{fixedAlias};
            }
            return null;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return delegate.chooseClientAlias(keyType, issuers, socket);
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return delegate.chooseEngineClientAlias(keyType, issuers, engine);
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return delegate.getClientAliases(keyType, issuers);
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return delegate.getCertificateChain(alias);
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return delegate.getPrivateKey(alias);
        }
    }

    private TlsContextFactory() {
    }

    // -----------------------------------------------------------------------------------------
    // Factory
    // -----------------------------------------------------------------------------------------

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

        String alias = firstServerAlias(ks);
        Certificate cert = ks.getCertificate(alias);
        String algo = cert != null && cert.getPublicKey() != null
                ? cert.getPublicKey().getAlgorithm()
                : "RSA";

        KeyManager[] wrapped = wrapKeyManagers(kmf.getKeyManagers(), alias, algo);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(wrapped, null, null);
        return ctx.getServerSocketFactory();
    }

    /**
     * Returns the first key-entry alias found in the keystore.
     */
    private static String firstServerAlias(KeyStore ks) throws Exception {
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                return alias;
            }
        }
        throw new IllegalStateException(
                "Keystore contains no key entries — cannot determine server certificate alias. "
                + "Check that the keystore path and password are correct and that it contains "
                + "at least one private key + certificate chain.");
    }

    private static KeyManager[] wrapKeyManagers(KeyManager[] kms, String fixedAlias, String algo) {
        KeyManager[] result = new KeyManager[kms.length];
        for (int i = 0; i < kms.length; i++) {
            if (kms[i] instanceof X509ExtendedKeyManager) {
                result[i] = new SniBlindKeyManager((X509ExtendedKeyManager) kms[i], fixedAlias, algo);
            } else if (kms[i] instanceof X509KeyManager) {
                result[i] = new X509KeyManagerAdapter((X509KeyManager) kms[i], fixedAlias, algo);
            } else {
                result[i] = kms[i];
            }
        }
        return result;
    }

    private static final class X509KeyManagerAdapter extends X509ExtendedKeyManager {

        private final X509KeyManager delegate;
        private final String fixedAlias;
        private final String keyAlgorithm;

        X509KeyManagerAdapter(X509KeyManager delegate, String fixedAlias, String keyAlgorithm) {
            this.delegate = delegate;
            this.fixedAlias = fixedAlias;
            this.keyAlgorithm = keyAlgorithm != null ? keyAlgorithm.toUpperCase() : "RSA";
        }

        private boolean isCompatible(String keyType) {
            if (keyType == null || keyType.isEmpty()) return true;
            String kt = keyType.toUpperCase();
            if ("RSA".equals(keyAlgorithm)) {
                return kt.contains("RSA") || "NONE".equals(kt);
            } else if ("EC".equals(keyAlgorithm)) {
                return kt.contains("EC") || "ECDSA".equals(kt);
            }
            return kt.contains(keyAlgorithm);
        }

        @Override
        public String chooseServerAlias(String t, Principal[] i, Socket s) {
            String a = delegate.chooseServerAlias(t, i, s);
            return a != null ? a : (isCompatible(t) ? fixedAlias : null);
        }

        @Override
        public String chooseEngineServerAlias(String t, Principal[] i, SSLEngine e) {
            return isCompatible(t) ? fixedAlias : null;
        }

        @Override
        public String[] getServerAliases(String t, Principal[] i) {
            String[] arr = delegate.getServerAliases(t, i);
            return (arr != null && arr.length > 0) ? arr : (isCompatible(t) ? new String[]{fixedAlias} : null);
        }

        @Override public String chooseClientAlias(String[] t, Principal[] i, Socket s) { return delegate.chooseClientAlias(t, i, s); }
        @Override public String chooseEngineClientAlias(String[] t, Principal[] i, SSLEngine e) { return null; }
        @Override public String[] getClientAliases(String t, Principal[] i) { return delegate.getClientAliases(t, i); }
        @Override public X509Certificate[] getCertificateChain(String a) { return delegate.getCertificateChain(a); }
        @Override public PrivateKey getPrivateKey(String a) { return delegate.getPrivateKey(a); }
    }

    // -----------------------------------------------------------------------------------------
    // Socket tuning
    // -----------------------------------------------------------------------------------------

    /**
     * Tune the listening server socket: enable broad protocol range and install the
     * permissive {@link AcceptAllSniMatcher}.
     */
    static void tuneServerSocket(SSLServerSocket ss) {
        try {
            ss.setEnabledProtocols(ss.getSupportedProtocols());
        } catch (Exception ignored) {
        }
        ss.setNeedClientAuth(false);
        ss.setWantClientAuth(false);

        try {
            SSLParameters params = ss.getSSLParameters();
            params.setSNIMatchers(Collections.singletonList(new AcceptAllSniMatcher()));
            ss.setSSLParameters(params);
        } catch (Exception ignored) {
        }
    }

    /**
     * Tune an accepted client socket before the handshake begins.
     * Crucial: ensures AcceptAllSniMatcher and supported protocols are explicitly
     * registered on the actual accepted SSLSocket instance, preventing JSSE from
     * reverting to default strict SNI handling on accepted connections.
     */
    static void tuneAcceptedSocket(Socket socket) {
        if (!(socket instanceof SSLSocket)) {
            return;
        }
        SSLSocket ssl = (SSLSocket) socket;
        try {
            ssl.setEnabledProtocols(ssl.getSupportedProtocols());
        } catch (Exception ignored) {
        }
        ssl.setNeedClientAuth(false);
        ssl.setWantClientAuth(false);

        try {
            SSLParameters params = ssl.getSSLParameters();
            params.setSNIMatchers(Collections.singletonList(new AcceptAllSniMatcher()));
            ssl.setSSLParameters(params);
        } catch (Exception ignored) {
        }
    }

    private static String guessType(String path) {
        String p = path.toLowerCase();
        if (p.endsWith(".p12") || p.endsWith(".pfx")) {
            return "PKCS12";
        }
        return "JKS";
    }
}
