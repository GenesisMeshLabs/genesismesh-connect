package org.genesismesh.connect.authority;

/** KeyInfo uses -1 for per-use authentication, unlike Builder's timeout=0. */
final class RootKeyPolicy {
    static boolean isPerUse(boolean required, int keyInfoSeconds, int types, int expectedTypes) {
        return required && keyInfoSeconds == -1 && types == expectedTypes;
    }
}
