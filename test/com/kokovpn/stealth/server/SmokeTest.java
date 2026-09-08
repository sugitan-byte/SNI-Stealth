package com.kokovpn.stealth.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Self-contained smoke test for the STEALTH server, using no TLS and loopback sockets so it needs
 * no keystore. It stands up an echo server as the SOCKS destination and a {@link StealthServer},
 * then drives three cases end to end:
 *
 * <ol>
 *   <li>correct token + plain injection -&gt; SOCKS5 bridge relays an echo;</li>
 *   <li>correct token + WebSocket upgrade -&gt; WebSocket bridge relays an echo through frames;</li>
 *   <li>no token (a probe) -&gt; the HTTP-200 fallback, never a bridge;</li>
 *   <li>no token, fallback=forward -&gt; transparently proxied to a decoy origin, which sees the
 *       original request bytes and whose response is piped back.</li>
 * </ol>
 *
 * Exits non-zero on any failure.
 */
public final class SmokeTest {

    private static final String TOKEN = "s3cr3t-smoke";
    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        int echoPort = startEchoServer();

        ServerConfig cfg = new ServerConfig();
        cfg.listenPort = 0;          // ephemeral
        cfg.useTls = false;          // no keystore needed for the logic test
        cfg.token = TOKEN;
        cfg.fallback = "http200";
        StealthServer server = new StealthServer(cfg);
        int port = server.startBackground();

        // A second server whose fallback transparently forwards to a plaintext decoy origin.
        int decoyPort = startDecoyOrigin();
        ServerConfig fwdCfg = new ServerConfig();
        fwdCfg.listenPort = 0;
        fwdCfg.useTls = false;
        fwdCfg.token = TOKEN;
        fwdCfg.fallback = "forward";
        fwdCfg.forwardHost = "127.0.0.1";
        fwdCfg.forwardPort = decoyPort;
        fwdCfg.forwardTls = "false";   // decoy speaks plaintext here
        StealthServer fwdServer = new StealthServer(fwdCfg);
        int fwdPort = fwdServer.startBackground();

        try {
            testSocksBridge(port, echoPort);
            testWebSocketBridge(port, echoPort);
            testProbeFallback(port);
            testTransparentForward(fwdPort);
        } finally {
            server.stop();
            fwdServer.stop();
        }

        if (failures == 0) {
            System.out.println("SMOKE TEST: ALL PASSED");
        } else {
            System.out.println("SMOKE TEST: " + failures + " FAILURE(S)");
            System.exit(1);
        }
    }

    // ---- case 1: plain injection -> SOCKS5 bridge ----
    private static void testSocksBridge(int serverPort, int echoPort) throws IOException {
        Socket s = new Socket("127.0.0.1", serverPort);
        s.setSoTimeout(5000);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();

        String head = "GET / HTTP/1.1\r\nHost: front.example\r\n"
                + "X-Stealth-Auth: " + TOKEN + "\r\n\r\n";
        out.write(head.getBytes("ISO-8859-1"));
        out.flush();

        socks5Connect(in, out, echoPort);
        String reply = echoRoundTrip(in, out, "hello-socks");
        check("SOCKS bridge echo", "hello-socks".equals(reply));
        s.close();
    }

    // ---- case 2: websocket upgrade -> WebSocket bridge ----
    private static void testWebSocketBridge(int serverPort, int echoPort) throws IOException {
        Socket s = new Socket("127.0.0.1", serverPort);
        s.setSoTimeout(5000);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();

        String head = "GET /ws HTTP/1.1\r\nHost: front.example\r\n"
                + "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
                + "X-Stealth-Auth: " + TOKEN + "\r\n\r\n";
        out.write(head.getBytes("ISO-8859-1"));
        out.flush();

        String status = readHttpHead(in);
        check("WS upgrade 101", status != null && status.contains(" 101"));

        // SOCKS5 over WebSocket binary frames (client masks).
        WsPipe ws = new WsPipe(in, out);
        // greeting
        ws.send(new byte[]{0x05, 0x01, 0x00});
        byte[] methodSel = ws.recv();
        check("WS socks method-select", methodSel.length == 2 && methodSel[0] == 0x05 && methodSel[1] == 0x00);
        // request CONNECT 127.0.0.1:echoPort
        ws.send(socksConnectRequest(echoPort));
        byte[] connReply = ws.recv();
        check("WS socks connect reply", connReply.length >= 2 && connReply[1] == 0x00);
        // echo
        ws.send("hello-ws".getBytes("US-ASCII"));
        byte[] echoed = ws.recv();
        check("WS bridge echo", new String(echoed, "US-ASCII").equals("hello-ws"));
        s.close();
    }

    // ---- case 3: no token -> fallback 200 ----
    private static void testProbeFallback(int serverPort) throws IOException {
        Socket s = new Socket("127.0.0.1", serverPort);
        s.setSoTimeout(5000);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        out.write("GET / HTTP/1.1\r\nHost: front.example\r\n\r\n".getBytes("ISO-8859-1"));
        out.flush();
        String status = readHttpHead(in);
        check("probe gets 200 fallback", status != null && status.contains("200 OK"));
        s.close();
    }

    // ---- case 4: no token, fallback=forward -> transparent proxy to a decoy origin ----
    private static void testTransparentForward(int serverPort) throws IOException {
        Socket s = new Socket("127.0.0.1", serverPort);
        s.setSoTimeout(5000);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        // A probe with no token; the request line carries a marker the decoy echoes back, proving
        // the head we already consumed was replayed to the origin verbatim.
        out.write("GET /probe-marker HTTP/1.1\r\nHost: decoy.example\r\n\r\n".getBytes("ISO-8859-1"));
        out.flush();
        String status = readHttpHead(in);
        check("forward fallback returns decoy response",
                status != null && status.contains("200 DECOY") && status.contains("/probe-marker"));
        s.close();
    }

    // ---- helpers ----
    private static void socks5Connect(InputStream in, OutputStream out, int port) throws IOException {
        out.write(new byte[]{0x05, 0x01, 0x00});
        out.flush();
        byte[] sel = readN(in, 2);
        check("socks method-select", sel[0] == 0x05 && sel[1] == 0x00);
        out.write(socksConnectRequest(port));
        out.flush();
        byte[] reply = readN(in, 10);
        check("socks connect reply", reply[1] == 0x00);
    }

    private static byte[] socksConnectRequest(int port) {
        return new byte[]{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
                (byte) ((port >> 8) & 0xff), (byte) (port & 0xff)};
    }

    private static String echoRoundTrip(InputStream in, OutputStream out, String msg) throws IOException {
        out.write(msg.getBytes("US-ASCII"));
        out.flush();
        byte[] back = readN(in, msg.length());
        return new String(back, "US-ASCII");
    }

    /** WebSocket framing pipe for the client side of the test (masked writes). */
    private static final class WsPipe {
        private final InputStream in;
        private final OutputStream out;
        WsPipe(InputStream in, OutputStream out) {
            this.in = in;
            this.out = out;
        }
        void send(byte[] data) throws IOException {
            WebSocketFrame.writeBinary(out, data, 0, data.length, true);
        }
        byte[] recv() throws IOException {
            byte[] m = WebSocketFrame.readMessage(in, out, true);
            return m == null ? new byte[0] : m;
        }
    }

    /** A plaintext decoy web server: reads the request line and echoes its path in the status. */
    private static int startDecoyOrigin() throws IOException {
        final ServerSocket ss = new ServerSocket();
        ss.bind(new InetSocketAddress("127.0.0.1", 0));
        Thread t = new Thread(new Runnable() {
            public void run() {
                while (true) {
                    try {
                        final Socket c = ss.accept();
                        new Thread(new Runnable() {
                            public void run() {
                                try {
                                    String firstLine = readHttpHead(c.getInputStream());
                                    String path = "";
                                    if (firstLine != null) {
                                        String[] parts = firstLine.split(" ");
                                        if (parts.length >= 2) {
                                            path = parts[1];
                                        }
                                    }
                                    String resp = "HTTP/1.1 200 DECOY " + path + "\r\n"
                                            + "Content-Length: 0\r\nConnection: close\r\n\r\n";
                                    OutputStream o = c.getOutputStream();
                                    o.write(resp.getBytes("ISO-8859-1"));
                                    o.flush();
                                } catch (IOException ignored) {
                                }
                            }
                        }).start();
                    } catch (IOException e) {
                        break;
                    }
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return ss.getLocalPort();
    }

    private static int startEchoServer() throws IOException {
        final ServerSocket ss = new ServerSocket();
        ss.bind(new InetSocketAddress("127.0.0.1", 0));
        Thread t = new Thread(new Runnable() {
            public void run() {
                while (true) {
                    try {
                        final Socket c = ss.accept();
                        new Thread(new Runnable() {
                            public void run() {
                                try {
                                    InputStream i = c.getInputStream();
                                    OutputStream o = c.getOutputStream();
                                    byte[] buf = new byte[4096];
                                    int n;
                                    while ((n = i.read(buf)) != -1) {
                                        o.write(buf, 0, n);
                                        o.flush();
                                    }
                                } catch (IOException ignored) {
                                }
                            }
                        }).start();
                    } catch (IOException e) {
                        break;
                    }
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return ss.getLocalPort();
    }

    private static String readHttpHead(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        String first = null;
        StringBuilder line = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\r') {
                continue;
            }
            if (b == '\n') {
                if (first == null) {
                    first = line.toString();
                }
                if (line.length() == 0) {
                    return first;
                }
                line.setLength(0);
            } else {
                line.append((char) b);
            }
            if (sb.length() > 16384) {
                break;
            }
        }
        return first;
    }

    private static byte[] readN(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int read = 0;
        while (read < n) {
            int r = in.read(buf, read, n - read);
            if (r < 0) {
                throw new IOException("short read: got " + read + " of " + n);
            }
            read += r;
        }
        return buf;
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  PASS  " : "  FAIL  ") + name);
        if (!ok) {
            failures++;
        }
    }
}
