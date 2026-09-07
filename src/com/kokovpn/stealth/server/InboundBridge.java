package com.kokovpn.stealth.server;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Handles the post-authentication stream of a verified client, connecting it to the outside world.
 * {@code in}/{@code out} are positioned immediately after the handshake head.
 */
interface InboundBridge {
    void handle(Socket client, InputStream in, OutputStream out, HandshakeReader.Head head) throws Exception;
}
