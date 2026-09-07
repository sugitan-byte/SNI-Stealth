package com.kokovpn.stealth.server;

/**
 * Decides whether an incoming handshake belongs to a genuine client or is an active probe.
 * Swap the implementation to change how clients prove themselves (static token, HMAC, time-based,
 * client-cert, …) without touching the listener or the bridges.
 */
interface AuthPolicy {
    boolean verify(HandshakeReader.Head head);
}
