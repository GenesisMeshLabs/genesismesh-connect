package org.genesismesh.connect.authority;

/** Public KeyInfo documentation says -1; current Keystore2 reports zero for per-use keys. */
final class RootKeyPolicy {
    static boolean isPerUse(boolean required, int keyInfoSeconds, int types, int expectedTypes) {
        return required && (keyInfoSeconds == -1 || keyInfoSeconds == 0) && types == expectedTypes;
    }
}
