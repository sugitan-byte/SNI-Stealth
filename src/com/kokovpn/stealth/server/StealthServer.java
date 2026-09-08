package com.kokovpn.stealth.server;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;

/**
 * Standalone STEALTH-Tunnel server. Accepts (optionally TLS-wrapped) connections and hands each to
 * a {@link ConnectionHandler} that smart-routes it to a bridge or the fallback.
 *
 * <p>Usage:
 * <pre>
 *   java -cp out com.kokovpn.stealth.server.StealthServer --config server.properties
 *   java -cp out com.kokovpn.stealth.server.StealthServer \
 *        --port 443 --keystore server.p12 --keystore-pass secret \
 *        --token s3cr3t --fallback forward --forward-host www.bing.com --forward-port 80
 * </pre>
 */
public final class StealthServer {

    private final ServerConfig cfg;
    private final AuthPolicy auth;
    private final InboundBridge socks5;
    private final InboundBridge websocket;
    private final InboundBridge mux;
    private final FallbackHandler fallback;
    private final ExecutorService pool;

    private volatile boolean running = false;
    private ServerSocket serverSocket;

    public StealthServer(ServerConfig cfg) {
        this.cfg = cfg;
        this.auth = new TokenAuthPolicy(cfg.token);
        this.socks5 = new Socks5Bridge();
        this.websocket = new WebSocketBridge();
        this.mux = new MuxBridge();
        this.fallback = "forward".equalsIgnoreCase(cfg.fallback)
                ? new TransparentForwardFallback(cfg.forwardHost, cfg.forwardPort, cfg.forwardTlsEnabled())
                : new HttpOkFallback();
        this.pool = Executors.newFixedThreadPool(Math.max(4, cfg.workerThreads));
    }

    /** Bind the listener and return the actual port (useful when {@code listenPort} is 0). */
    public int bind() throws Exception {
        ServerSocket ss;
        if (cfg.useTls) {
            ServerSocketFactory f = TlsContextFactory.serverSocketFactory(cfg);
            SSLServerSocket sslss = (SSLServerSocket) f.createServerSocket();
            TlsContextFactory.tuneServerSocket(sslss);
            ss = sslss;
        } else {
            ss = new ServerSocket();
        }
        ss.setReuseAddress(true);
        ss.bind(new InetSocketAddress("0.0.0.0", cfg.listenPort));
        this.serverSocket = ss;
        this.running = true;
        return ss.getLocalPort();
    }

    /** Run the accept loop on the calling thread until {@link #stop()}. */
    public void serve() {
        log("STEALTH server listening on " + serverSocket.getLocalPort()
                + " (tls=" + cfg.useTls + ", fallback=" + cfg.fallback + ")");
        while (running) {
            final Socket client;
            try {
                client = serverSocket.accept();
            } catch (IOException e) {
                if (running) {
                    continue;
                }
                break;
            }
            pool.submit(new ConnectionHandler(client, auth, socks5, websocket, mux, fallback));
        }
    }

    /** Bind and run the accept loop on a background daemon thread; returns the bound port. */
    public int startBackground() throws Exception {
        int port = bind();
        Thread t = new Thread(new Runnable() {
            public void run() {
                serve();
            }
        }, "stealth-accept");
        t.setDaemon(true);
        t.start();
        return port;
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
        }
        pool.shutdownNow();
    }

    private static void log(String msg) {
        System.out.println("[stealth] " + msg);
    }

    public static void main(String[] args) throws Exception {
        ServerConfig cfg = ServerConfig.fromArgs(args);
        if (cfg.token == null || cfg.token.isEmpty()) {
            log("WARNING: no --token set; every well-formed client will be accepted.");
        }
        StealthServer server = new StealthServer(cfg);
        server.bind();
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            public void run() {
                server.stop();
            }
        }));
        server.serve();
    }
}
