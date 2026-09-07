package com.kokovpn.stealth.server;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Server configuration, from a {@code .properties} file and/or command-line flags. Flags override
 * file values. Everything has a sensible default except the auth token, which should always be set.
 */
public final class ServerConfig {

    public int listenPort = 8443;
    public boolean useTls = true;               // false when TLS is terminated upstream (nginx/CDN) or for tests
    public String keystorePath = "";            // JKS/PKCS12 keystore for the server certificate
    public String keystorePass = "";
    public String token = "";                   // shared secret a genuine client sends in X-Stealth-Auth

    public String bridge = "auto";              // "auto" | "socks5" | "websocket"

    public String fallback = "http200";         // "http200" | "forward"
    public String forwardHost = "example.com";  // decoy origin for fallback=forward
    public int forwardPort = 80;

    public int workerThreads = 512;

    public static ServerConfig fromArgs(String[] args) throws IOException {
        ServerConfig cfg = new ServerConfig();
        // First pass: load a --config properties file if present.
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals("--config")) {
                cfg.loadProperties(args[i + 1]);
            }
        }
        // Second pass: explicit flags override the file.
        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            switch (a) {
                case "--port":         cfg.listenPort = Integer.parseInt(next(args, ++i)); break;
                case "--no-tls":       cfg.useTls = false; break;
                case "--tls":          cfg.useTls = true; break;
                case "--keystore":     cfg.keystorePath = next(args, ++i); break;
                case "--keystore-pass":cfg.keystorePass = next(args, ++i); break;
                case "--token":        cfg.token = next(args, ++i); break;
                case "--bridge":       cfg.bridge = next(args, ++i); break;
                case "--fallback":     cfg.fallback = next(args, ++i); break;
                case "--forward-host": cfg.forwardHost = next(args, ++i); break;
                case "--forward-port": cfg.forwardPort = Integer.parseInt(next(args, ++i)); break;
                default: break;
            }
        }
        return cfg;
    }

    private void loadProperties(String path) throws IOException {
        Properties p = new Properties();
        FileInputStream in = new FileInputStream(path);
        try {
            p.load(in);
        } finally {
            in.close();
        }
        listenPort   = intProp(p, "listenPort", listenPort);
        useTls       = boolProp(p, "useTls", useTls);
        keystorePath = p.getProperty("keystorePath", keystorePath);
        keystorePass = p.getProperty("keystorePass", keystorePass);
        token        = p.getProperty("token", token);
        bridge       = p.getProperty("bridge", bridge);
        fallback     = p.getProperty("fallback", fallback);
        forwardHost  = p.getProperty("forwardHost", forwardHost);
        forwardPort  = intProp(p, "forwardPort", forwardPort);
        workerThreads = intProp(p, "workerThreads", workerThreads);
    }

    private static String next(String[] args, int i) {
        if (i >= args.length) {
            throw new IllegalArgumentException("missing value for flag");
        }
        return args[i];
    }

    private static int intProp(Properties p, String k, int def) {
        String v = p.getProperty(k);
        return v == null ? def : Integer.parseInt(v.trim());
    }

    private static boolean boolProp(Properties p, String k, boolean def) {
        String v = p.getProperty(k);
        return v == null ? def : Boolean.parseBoolean(v.trim());
    }
}
