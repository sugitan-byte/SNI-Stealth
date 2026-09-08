package com.kokovpn.stealth.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reads an HTTP-style request head (request line + headers up to the blank line) one byte at a
 * time, so nothing belonging to the following stream (the SOCKS5 greeting, or WebSocket frames) is
 * swallowed. Keeps the exact raw bytes so the transparent-forward fallback can replay them to a
 * decoy origin verbatim.
 */
final class HandshakeReader {

    /** Parsed request head. Header keys are lower-cased for case-insensitive lookup. */
    static final class Head {
        final String requestLine;
        final String method;
        final String path;
        final Map<String, String> headers;
        final byte[] raw;

        Head(String requestLine, String method, String path, Map<String, String> headers, byte[] raw) {
            this.requestLine = requestLine;
            this.method = method;
            this.path = path;
            this.headers = headers;
            this.raw = raw;
        }

        String header(String name) {
            return headers.get(name.toLowerCase());
        }

        boolean isWebSocketUpgrade() {
            String up = header("upgrade");
            return up != null && up.toLowerCase().contains("websocket");
        }

        /** True when the client asked to multiplex many streams over this one connection. */
        boolean isMux() {
            return header("x-stealth-mux") != null;
        }
    }

    private static final int MAX_HEAD = 32 * 1024;

    private HandshakeReader() {
    }

    /** Read and parse the head, or return {@code null} if the peer closed before a blank line. */
    static Head read(InputStream in) throws IOException {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        int c;
        int crlfState = 0; // progress through \r\n\r\n
        while ((c = in.read()) != -1) {
            raw.write(c);
            if (c == '\r') {
                crlfState = (crlfState == 2) ? 3 : 1;
            } else if (c == '\n') {
                if (crlfState == 1) {
                    crlfState = 2;
                } else if (crlfState == 3) {
                    return parse(raw.toByteArray());
                } else {
                    crlfState = 0;
                }
            } else {
                crlfState = 0;
            }
            if (raw.size() > MAX_HEAD) {
                return parse(raw.toByteArray());
            }
        }
        if (raw.size() == 0) {
            return null;
        }
        return parse(raw.toByteArray());
    }

    private static Head parse(byte[] rawBytes) {
        String text;
        try {
            text = new String(rawBytes, "ISO-8859-1");
        } catch (Exception e) {
            text = new String(rawBytes);
        }
        String[] lines = text.split("\r\n");
        String requestLine = lines.length > 0 ? lines[0] : "";
        String method = "";
        String path = "";
        String[] parts = requestLine.split(" ");
        if (parts.length >= 2) {
            method = parts[0];
            path = parts[1];
        }
        Map<String, String> headers = new LinkedHashMap<String, String>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            if (line.isEmpty()) {
                break;
            }
            int colon = line.indexOf(':');
            if (colon > 0) {
                String key = line.substring(0, colon).trim().toLowerCase();
                String value = line.substring(colon + 1).trim();
                headers.put(key, value);
            }
        }
        return new Head(requestLine, method, path, headers, rawBytes);
    }
}
