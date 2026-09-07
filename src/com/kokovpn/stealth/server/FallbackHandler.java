package com.kokovpn.stealth.server;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Handles connections that failed authentication — random scanners, TLS crawlers, GFW active
 * probes. The goal is that such a peer sees an ordinary, boring web server, never a hint of a
 * proxy, so the port is uninteresting to block.
 */
interface FallbackHandler {
    void handle(Socket client, InputStream in, OutputStream out, HandshakeReader.Head head) throws Exception;
}
