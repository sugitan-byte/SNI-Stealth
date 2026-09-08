package com.kokovpn.stealth.server;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Server side of the stream multiplexer. After the token handshake, a client that asked for mux
 * (header {@code X-Stealth-Mux: 1}) sends {@link MuxFrame} frames instead of a single SOCKS5 stream.
 * This reads them off the one connection and, for every logical stream, runs the ordinary
 * {@link Socks5Bridge} core over a pair of adapters — a queue-backed input fed by that stream's DATA
 * frames, and an output that re-frames each write back to the client. So one TLS connection fans out
 * to hundreds of independent SOCKS5 conversations, and the phone pays a single handshake.
 */
final class MuxBridge implements InboundBridge {

    @Override
    public void handle(Socket client, InputStream in, OutputStream out, HandshakeReader.Head head)
            throws Exception {
        final OutputStream muxOut = out;
        final Map<Integer, StreamCtx> streams = new ConcurrentHashMap<Integer, StreamCtx>();
        try {
            MuxFrame.Frame f;
            while ((f = MuxFrame.read(in)) != null) {
                switch (f.type) {
                    case MuxFrame.OPEN: {
                        StreamCtx ctx = new StreamCtx(f.streamId, muxOut, streams);
                        streams.put(f.streamId, ctx);
                        ctx.start();
                        break;
                    }
                    case MuxFrame.DATA: {
                        StreamCtx ctx = streams.get(f.streamId);
                        if (ctx != null) {
                            ctx.feed(f.payload);
                        }
                        break;
                    }
                    case MuxFrame.CLOSE: {
                        StreamCtx ctx = streams.remove(f.streamId);
                        if (ctx != null) {
                            ctx.closeInput();
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
        } finally {
            for (StreamCtx c : streams.values()) {
                c.closeInput();
            }
            streams.clear();
            try {
                client.close();
            } catch (IOException ignored) {
            }
        }
    }

    /** One logical stream: a queue-fed input, a re-framing output, and a SOCKS5 worker over them. */
    private static final class StreamCtx {
        private final int id;
        private final OutputStream muxOut;
        private final Map<Integer, StreamCtx> streams;
        private final QueueInputStream input = new QueueInputStream();

        StreamCtx(int id, OutputStream muxOut, Map<Integer, StreamCtx> streams) {
            this.id = id;
            this.muxOut = muxOut;
            this.streams = streams;
        }

        void feed(byte[] payload) {
            input.offer(payload);
        }

        void closeInput() {
            input.eof();
        }

        void start() {
            final InputStream sin = input;
            final OutputStream sout = new StreamOutput(muxOut, id);
            Thread t = new Thread(new Runnable() {
                public void run() {
                    try {
                        Socks5Bridge.run(sin, sout, new Runnable() {
                            public void run() {
                                closeStream();
                            }
                        });
                    } catch (IOException e) {
                        closeStream();
                    }
                }
            }, "mux-stream-" + id);
            t.setDaemon(true);
            t.start();
        }

        private void closeStream() {
            streams.remove(id);
            try {
                MuxFrame.writeClose(muxOut, id);
            } catch (IOException ignored) {
            }
        }
    }

    /** Each write becomes DATA frames for this stream, back to the client over the shared output. */
    private static final class StreamOutput extends OutputStream {
        private final OutputStream muxOut;
        private final int id;

        StreamOutput(OutputStream muxOut, int id) {
            this.muxOut = muxOut;
            this.id = id;
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[]{(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            MuxFrame.writeData(muxOut, id, b, off, len);
        }

        @Override
        public void flush() {
        }
    }

    /** Blocking input backed by a queue of DATA payloads, terminated by an EOF sentinel. */
    private static final class QueueInputStream extends InputStream {
        private static final byte[] EOF = new byte[0];
        private final BlockingQueue<byte[]> queue = new LinkedBlockingQueue<byte[]>();
        private byte[] cur = null;
        private int pos = 0;
        private boolean done = false;

        void offer(byte[] payload) {
            if (payload != null && payload.length > 0) {
                queue.offer(payload);
            }
        }

        void eof() {
            queue.offer(EOF);
        }

        @Override
        public int read() throws IOException {
            if (!ensure()) {
                return -1;
            }
            return cur[pos++] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (!ensure()) {
                return -1;
            }
            int n = Math.min(len, cur.length - pos);
            System.arraycopy(cur, pos, b, off, n);
            pos += n;
            return n;
        }

        private boolean ensure() throws IOException {
            while (cur == null || pos >= cur.length) {
                if (done) {
                    return false;
                }
                byte[] next;
                try {
                    next = queue.take();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted");
                }
                if (next == EOF) {
                    done = true;
                    return false;
                }
                cur = next;
                pos = 0;
            }
            return true;
        }
    }
}
