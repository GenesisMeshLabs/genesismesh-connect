package org.genesismesh.connect.authoritycheck;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class EngineCheckRunnerTest {
    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("Engine generation or serialization failed");
    }
    private static void await(CountDownLatch latch) {
        try { require(latch.await(5, TimeUnit.SECONDS)); }
        catch (InterruptedException error) { throw new AssertionError(error); }
    }
    public static void main(String[] args) throws Exception {
        List<Runnable> jobs = new ArrayList<>();
        List<Runnable> ui = new ArrayList<>();
        EngineCheckRunner<String> runner = new EngineCheckRunner<>(jobs::add);
        AtomicReference<String> disk = new AtomicReference<>();
        AtomicReference<String> screen = new AtomicReference<>();
        AtomicInteger startups = new AtomicInteger();
        AtomicInteger active = new AtomicInteger();
        AtomicInteger peak = new AtomicInteger();
        AtomicReference<Boolean> pythonStarted = new AtomicReference<>(false);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        EngineCheckRunner.Listener<String> listener = new EngineCheckRunner.Listener<String>() {
            public void started(String id) { disk.set(id + ":running"); }
            public void completed(String id, String result) {
                disk.set(id + ":" + result);
                ui.add(() -> runner.publishIfActive(id, () -> screen.set(result)));
            }
        };
        String old = runner.start(() -> {
            peak.accumulateAndGet(active.incrementAndGet(), Math::max);
            if (!pythonStarted.get()) startups.incrementAndGet();
            entered.countDown(); await(release); pythonStarted.set(true);
            active.decrementAndGet(); return "passed";
        }, listener);
        Thread first = new Thread(jobs.remove(0)); first.start(); await(entered);
        CountDownLatch secondAttempted = new CountDownLatch(1);
        String current = runner.start(() -> {
            peak.accumulateAndGet(active.incrementAndGet(), Math::max);
            if (!pythonStarted.get()) { startups.incrementAndGet(); pythonStarted.set(true); }
            active.decrementAndGet(); return "failed";
        }, listener);
        Thread second = new Thread(() -> { secondAttempted.countDown(); jobs.remove(0).run(); });
        second.start(); await(secondAttempted);
        try {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (second.isAlive() && second.getState() != Thread.State.BLOCKED
                    && System.nanoTime() < deadline) Thread.yield();
            require(second.getState() == Thread.State.BLOCKED);
        } finally { release.countDown(); }
        first.join(5000); second.join(5000);
        require(!first.isAlive() && !second.isAlive());
        require(!old.equals(current) && startups.get() == 1 && peak.get() == 1);
        require(disk.get().equals(current + ":failed") && ui.size() == 1);
        ui.remove(0).run(); require(screen.get().equals("failed"));

        // A completion already queued on an old Activity's UI cannot replace a newer failure.
        runner.start(() -> "passed", listener); jobs.remove(0).run();
        Runnable delayedUi = ui.remove(0);
        String latest = runner.start(() -> "failed", listener); jobs.remove(0).run();
        ui.remove(0).run(); delayedUi.run();
        require(disk.get().equals(latest + ":failed") && screen.get().equals("failed"));
        System.out.println("Serialized startup and stale report/UI refusal passed");
    }
}
