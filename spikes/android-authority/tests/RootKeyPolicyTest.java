package org.genesismesh.connect.authority;

public final class RootKeyPolicyTest {
    public static void main(String[] args) {
        if (!RootKeyPolicy.isPerUse(true, -1, 3, 3)) throw new AssertionError("KeyInfo per-use key refused");
        if (!RootKeyPolicy.isPerUse(true, 0, 3, 3)) throw new AssertionError("Keystore2 per-use key refused");
        for (int seconds : new int[] {-2, 1, 30, 300}) {
            if (RootKeyPolicy.isPerUse(true, seconds, 3, 3)) throw new AssertionError("Timed/unknown key accepted");
        }
        if (RootKeyPolicy.isPerUse(false, -1, 3, 3)) throw new AssertionError("Unauthenticated key accepted");
        for (int types : new int[] {0, 1, 2, 7}) {
            if (RootKeyPolicy.isPerUse(true, -1, types, 3)) throw new AssertionError("Unexpected authenticator accepted");
        }
    }
}
