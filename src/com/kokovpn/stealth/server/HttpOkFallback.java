package com.kokovpn.stealth.server;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Answers an unverified peer with a plain {@code 200 OK} and a tiny generic page, then closes.
 * Looks like a low-traffic default web server.
 */
final class HttpOkFallback implements FallbackHandler {

    private static final String BODY =
            "<!doctype html><html><head><title>Welcome</title></head>"
          + "<body><h1>It works!</h1></body></html>";

    @Override
    public void handle(Socket client, InputStream in, OutputStream out, HandshakeReader.Head head)
            throws Exception {
        byte[] body = BODY.getBytes("UTF-8");
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 200 OK\r\n");
        sb.append("Server: nginx\r\n");
        sb.append("Content-Type: text/html; charset=utf-8\r\n");
        sb.append("Content-Length: ").append(body.length).append("\r\n");
        sb.append("Connection: close\r\n");
        sb.append("\r\n");
        out.write(sb.toString().getBytes("ISO-8859-1"));
        out.write(body);
        out.flush();
        client.close();
    }
}
