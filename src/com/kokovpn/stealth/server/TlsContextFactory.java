package com.kokovpn.stealth.server;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
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
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

/**
 * Builds the server's TLS listener from a keystore. The server must present a certificate to speak
 * TLS at all; the stealth client deliberately does not validate it (the identity check is the
 * injected token, not the certificate), which is what lets a single IP wear any SNI/front name.
 *
 * <p>JSSE's default behaviour is to RST the connection when the client sends a ClientHello whose
 * SNI does not match any name in the server's certificate (CN or SANs). This is unlike OpenSSL /
 * Stunnel, which complete the handshake and present the certificate regardless. The fix requires
 * two cooperating components:
 *
 * <ol>
 *   <li>{@link AcceptAllSniMatcher} — suppresses the SNI-matching rejection at the
 *       {@link SSLParameters} layer, so JSSE does not send {@code unrecognized_name}.
 *   <li>{@link SniBlindKeyManager} — wraps the real {@link X509ExtendedKeyManager} so
 *       {@code chooseServerAlias} / {@code chooseEngineServerAlias} always return the first
 *       available certificate alias, ignoring the requested SNI entirely. Without this second
 *       fix the default key manager's SNI-aware alias lookup returns {@code null} for any
 *       hostname that does not match the certificate's CN/SANs, causing JSSE to abort the
 *       handshake with {@code SSL_HANDSHAKE_FAILURE} (BoringSSL error 0x100000d7) even though
 *       the SNI matcher already returned {@code true}.
 * </ol>
 */
final class TlsContextFactory {

    // -----------------------------------------------------------------------------------------
    // AcceptAllSniMatcher
    // -----------------------------------------------------------------------------------------

    /**
     * An {@link SNIMatcher} that accepts every SNI value the client sends, regardless of whether
     * it matches the server certificate's CN or any SAN. JSSE consults the matcher registered on
     * {@link SSLParameters} before deciding to alert/RST; returning {@code true} here suppresses
     * the mismatch rejection so the handshake always completes at the SNI-matching layer.
     *
     * <p>This alone is NOT sufficient — the {@link SniBlindKeyManager} is also required so the
     * key manager layer does not independently reject the SNI mismatch.
     */
    private static final class AcceptAllSniMatcher extends SNIMatcher {
        AcceptAllSniMatcher() {
            super(0); // type 0 = RFC 6066 host_name, the only type clients send today
        }

        @Override
        public boolean matches(SNIServerName serverName) {
            return true; // accept all — auth is the X-Stealth-Auth token, not the TLS name
        }
    }

    // -----------------------------------------------------------------------------------------
    // SniBlindKeyManager
    // -----------------------------------------------------------------------------------------

    /**
     * Wraps the real {@link X509ExtendedKeyManager} and overrides the alias-selection methods so
     * they always return the first available server certificate alias, completely ignoring the
     * requested SNI hostname.
     *
     * <h3>Why this is needed</h3>
     *
     * <p>JSSE's handshake pipeline has two independent SNI checks that both run on every
     * connection:
     *
     * <ol>
     *   <li>The {@link SNIMatcher} registered on {@link SSLParameters} — fixed by
     *       {@link AcceptAllSniMatcher}.
     *   <li>The key manager's {@code chooseServerAlias} / {@code chooseEngineServerAlias} — those
     *       methods receive the SNI hostname as a hint and, in Sun's default implementation
     *       ({@code sun.security.ssl.X509KeyManagerImpl}), filter the keystore aliases to only
     *       those whose certificate matches the requested hostname. When no alias matches (i.e.
     *       the client sent {@code mpu-ecommerce.com} but the keystore only has a cert for
     *       {@code myserver.example.com}) the method returns {@code null}. JSSE then has no
     *       certificate to present and aborts the handshake with {@code SSL_HANDSHAKE_FAILURE}.
     * </ol>
     *
     * <p>The fix is to delegate all certificate/key operations to the real key manager but
     * override only the alias-selection methods, making them unconditionally return whatever alias
     * the keystore has — matching Stunnel's behaviour of presenting the configured certificate
     * regardless of what SNI the client requested.
     */
    private static final class SniBlindKeyManager extends X509ExtendedKeyManager {

        private final X509ExtendedKeyManager delegate;
        private final String fixedAlias;

        /**
         * @param delegate  the real key manager produced by {@link KeyManagerFactory}
         * @param fixedAlias the first server-cert alias found in the keystore; used as the
         *                   unconditional return value of all alias-selection methods
         */
        SniBlindKeyManager(X509ExtendedKeyManager delegate, String fixedAlias) {
            this.delegate = delegate;
            this.fixedAlias = fixedAlias;
        }

        // -- Alias selection: always return our fixed alias regardless of SNI / issuers --------

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            // Ignore keyType filter and issuers — return the fixed alias unconditionally.
            // The real key manager would filter by hostname here; we don't.
            return fixedAlias;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            // Called instead of chooseServerAlias when using NIO/SSLEngine paths.
            return fixedAlias;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return delegate.chooseClientAlias(keyType, issuers, socket);
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return delegate.chooseEngineClientAlias(keyType, issuers, engine);
        }

        // -- Everything else: pure delegation ------------------------------------------------

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return delegate.getServerAliases(keyType, issuers);
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

    // -----------------------------------------------------------------------------------------
    // AcceptAllSniMatcher — already defined above
    // -----------------------------------------------------------------------------------------

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

        // Wrap every X509ExtendedKeyManager produced by the factory with SniBlindKeyManager so
        // alias selection always returns the fixed server certificate, regardless of the SNI the
        // client sent. Without this, the default implementation returns null for any SNI that
        // doesn't match the cert's CN/SANs, aborting the handshake (BoringSSL 0x100000d7).
        String alias = firstServerAlias(ks);
        KeyManager[] wrapped = wrapKeyManagers(kmf.getKeyManagers(), alias);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(wrapped, null, null);
        return ctx.getServerSocketFactory();
    }

    /**
     * Returns the first key-entry alias found in the keystore, which is the certificate the
     * server will always present to clients regardless of their SNI.
     *
     * @throws IllegalStateException if the keystore contains no key entries at all
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

    /**
     * Replaces every {@link X509ExtendedKeyManager} in the array with a {@link SniBlindKeyManager}
     * wrapping it. Managers of other types are passed through unchanged (they are unusual but
     * technically valid).
     */
    private static KeyManager[] wrapKeyManagers(KeyManager[] kms, String fixedAlias) {
        KeyManager[] result = new KeyManager[kms.length];
        for (int i = 0; i < kms.length; i++) {
            if (kms[i] instanceof X509ExtendedKeyManager) {
                result[i] = new SniBlindKeyManager((X509ExtendedKeyManager) kms[i], fixedAlias);
            } else if (kms[i] instanceof X509KeyManager) {
                // Rare: a non-extended X509KeyManager. Wrap it via an adapter so we still
                // override alias selection. In practice KeyManagerFactory always produces
                // X509ExtendedKeyManager, so this branch is defensive only.
                result[i] = new X509KeyManagerAdapter((X509KeyManager) kms[i], fixedAlias);
            } else {
                result[i] = kms[i];
            }
        }
        return result;
    }

    /**
     * Adapter that promotes a plain {@link X509KeyManager} (no engine methods) to an
     * {@link X509ExtendedKeyManager} with fixed alias selection. Used defensively for the
     * (extremely rare) case where a provider returns a non-extended key manager.
     */
    private static final class X509KeyManagerAdapter extends X509ExtendedKeyManager {

        private final X509KeyManager delegate;
        private final String fixedAlias;

        X509KeyManagerAdapter(X509KeyManager delegate, String fixedAlias) {
            this.delegate = delegate;
            this.fixedAlias = fixedAlias;
        }

        @Override public String chooseServerAlias(String t, Principal[] i, Socket s) { return fixedAlias; }
        @Override public String chooseEngineServerAlias(String t, Principal[] i, SSLEngine e) { return fixedAlias; }
        @Override public String chooseClientAlias(String[] t, Principal[] i, Socket s) { return delegate.chooseClientAlias(t, i, s); }
        @Override public String[] getServerAliases(String t, Principal[] i) { return delegate.getServerAliases(t, i); }
        @Override public String[] getClientAliases(String t, Principal[] i) { return delegate.getClientAliases(t, i); }
        @Override public X509Certificate[] getCertificateChain(String a) { return delegate.getCertificateChain(a); }
        @Override public PrivateKey getPrivateKey(String a) { return delegate.getPrivateKey(a); }
    }

    // -----------------------------------------------------------------------------------------
    // Socket tuning
    // -----------------------------------------------------------------------------------------

    /**
     * Enable a broad protocol range so old clients still negotiate, disable client auth,
     * and install the permissive {@link AcceptAllSniMatcher} so JSSE never rejects a ClientHello
     * whose SNI does not match the server certificate at the SNI-matching layer.
     *
     * <p>The key-manager layer is handled separately by {@link SniBlindKeyManager}, injected
     * into the {@link SSLContext} in {@link #serverSocketFactory}.
     */
    static void tuneServerSocket(SSLServerSocket ss) {
        try {
            ss.setEnabledProtocols(ss.getSupportedProtocols());
        } catch (Exception ignored) {
        }
        ss.setNeedClientAuth(false);
        ss.setWantClientAuth(false);

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
