package org.genesismesh.connect.authoritycheck;

import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

/** Process-wide execution and generation-bound publication, independent of Activity lifetime. */
final class EngineCheckRunner<T> {
    interface Listener<T> {
        void started(String runId);
        void completed(String runId, T result);
    }

    private final Executor executor;
    private final Object execution = new Object();
    private String activeRun;

    EngineCheckRunner(Executor executor) { this.executor = executor; }

    synchronized String start(Supplier<T> check, Listener<T> listener) {
        String runId = UUID.randomUUID().toString();
        activeRun = runId;
        listener.started(runId);
        executor.execute(() -> {
            synchronized (execution) {
                synchronized (this) { if (!runId.equals(activeRun)) return; }
                T result = check.get();
                publishIfActive(runId, () -> listener.completed(runId, result));
            }
        });
        return runId;
    }

    synchronized void publishIfActive(String runId, Runnable publication) {
        if (runId.equals(activeRun)) publication.run();
    }
}
