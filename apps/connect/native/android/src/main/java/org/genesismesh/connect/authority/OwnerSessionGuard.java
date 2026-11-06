package org.genesismesh.connect.authority;

import java.util.UUID;

/**
 * One live session at a time; reservation precedes Python execution. A new
 * session begins only after the previous one stopped and its owner closed
 * cleanly. No replay/reset API: durable core intents decide what a reopened
 * session may finish.
 */
public final class OwnerSessionGuard {
    private static final long MAX_SEQUENCE = (1L << 53) - 1;
    private String session;
    private long next = 1;
    private boolean stopped;
    private boolean released;

    public synchronized void begin(String id) {
        if (id == null || !UUID.fromString(id).toString().equals(id) || id.equals(session)
                || (session != null && !(stopped && released))) {
            throw new IllegalStateException("Close the previous owner session before another.");
        }
        session = id;
        next = 1;
        stopped = false;
        released = false;
    }

    public synchronized void reserve(String id, long sequence) {
        if (stopped || session == null || !session.equals(id) || sequence != next || next > MAX_SEQUENCE) {
            throw new IllegalStateException("Stale or repeated owner operation.");
        }
        next++;
    }

    public synchronized boolean current(String id) { return !stopped && session != null && session.equals(id); }
    public synchronized boolean belongs(String id) { return session != null && session.equals(id); }
    public synchronized void stop() { stopped = true; }

    /** The stopped session's owner closed and released its storage lock. */
    public synchronized void released(String id) {
        if (stopped && session != null && session.equals(id)) released = true;
    }
}
