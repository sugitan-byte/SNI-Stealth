package com.kokovpn.stealth.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Terminates the tunnel by acting as a SOCKS5 server over the (already authenticated) stream. The
 * client forwarded its device's tun2socks SOCKS5 conversation through the stealth transport; here
 * we negotiate it, make the outbound connection, and relay. Only CONNECT is supported, which is all
 * tun2socks needs.
 */
final class Socks5Bridge implements InboundBridge {

    private static final int CONNECT_TIMEOUT_MS = 15000;

    @Override
    public void handle(Socket client, InputStream in, OutputStream out, HandshakeReader.Head head)
            throws Exception {
        run(in, out, closer(client));
    }

    /** SOCKS5 core over arbitrary streams (reused by the WebSocket bridge). */
    static void run(InputStream cin, OutputStream cout, Runnable onClose) throws IOException {
        // Greeting: VER, NMETHODS, METHODS...
        int ver = cin.read();
        if (ver != 0x05) {
            onClose.run();
            return;
        }
        int nMethods = readByte(cin);
        readN(cin, nMethods); // ignore offered methods
        cout.write(new byte[]{0x05, 0x00}); // choose "no authentication"
        cout.flush();

        // Request: VER, CMD, RSV, ATYP, ADDR, PORT
        readByte(cin);                 // ver
        int cmd = readByte(cin);
        readByte(cin);                 // rsv
        int atyp = readByte(cin);
        String host;
        switch (atyp) {
            case 0x01: { // IPv4
                byte[] a = readN(cin, 4);
                host = (a[0] & 0xff) + "." + (a[1] & 0xff) + "." + (a[2] & 0xff) + "." + (a[3] & 0xff);
                break;
            }
            case 0x03: { // domain
                int len = readByte(cin);
                host = new String(readN(cin, len), "US-ASCII");
                break;
            }
            case 0x04: { // IPv6
                byte[] a = readN(cin, 16);
                host = java.net.InetAddress.getByAddress(a).getHostAddress();
                break;
            }
            default:
                reply(cout, 0x08); // address type not supported
                onClose.run();
                return;
        }
        int port = (readByte(cin) << 8) | readByte(cin);

        if (cmd != 0x01) {            // only CONNECT
            reply(cout, 0x07);        // command not supported
            onClose.run();
            return;
        }

        final Socket remote = new Socket();
        try {
            remote.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            remote.setTcpNoDelay(true);
        } catch (IOException e) {
            System.out.println("[stealth] CONNECT " + host + ":" + port + " FAILED " + e.getMessage());
            reply(cout, 0x05);        // connection refused / unreachable
            onClose.run();
            closeQuietly(remote);
            return;
        }

        reply(cout, 0x00);            // success
        StreamRelay.pipe(cin, cout, remote.getInputStream(), remote.getOutputStream(),
                new Runnable() {
                    public void run() {
                        closeQuietly(remote);
                        onClose.run();
                    }
                });
    }

    private static void reply(OutputStream cout, int rep) throws IOException {
        // VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0
        cout.write(new byte[]{0x05, (byte) rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
        cout.flush();
    }

    private static Runnable closer(final Socket s) {
        return new Runnable() {
            public void run() {
                closeQuietly(s);
            }
        };
    }

    private static int readByte(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) {
            throw new IOException("unexpected end of SOCKS stream");
        }
        return b;
    }

    private static byte[] readN(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int read = 0;
        while (read < n) {
            int r = in.read(buf, read, n - read);
            if (r < 0) {
                throw new IOException("unexpected end of SOCKS stream");
            }
            read += r;
        }
        return buf;
    }

    private static void closeQuietly(Socket s) {
        try {
            if (s != null) {
                s.close();
            }
        } catch (IOException ignored) {
        }
    }
}
