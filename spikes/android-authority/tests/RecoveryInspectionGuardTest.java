package org.genesismesh.connect.authority;
import java.util.UUID;

public final class RecoveryInspectionGuardTest {
    private static void refused(Runnable action) {
        try { action.run(); } catch (RuntimeException expected) { return; }
        throw new AssertionError("Reused or foreign inspection accepted");
    }
    public static void main(String[] args) {
        OwnerSessionGuard writer = new OwnerSessionGuard();
        String old = UUID.randomUUID().toString(); writer.begin(old); writer.reserve(old, 1); writer.stop();
        RecoveryInspectionGuard reader = new RecoveryInspectionGuard();
        refused(() -> reader.reserve(old, 1, writer));
        String fresh = UUID.randomUUID().toString(); reader.reserve(fresh, 1, writer);
        refused(() -> reader.reserve(fresh, 1, writer));
        refused(() -> reader.reserve(UUID.randomUUID().toString(), 2, writer));
        refused(() -> writer.reserve(old, 2));
        if (writer.current(old) || !writer.belongs(old)) throw new AssertionError("Writer fence was changed");
        for (int i = 1; i < 64; i++) reader.reserve(UUID.randomUUID().toString(), 1, writer);
        refused(() -> reader.reserve(UUID.randomUUID().toString(), 1, writer));
    }
}
