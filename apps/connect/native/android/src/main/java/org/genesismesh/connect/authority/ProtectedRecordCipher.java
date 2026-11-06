package org.genesismesh.connect.authority;

import javax.crypto.Cipher;

/** Use an initialized cipher only after its per-operation authorization completes. */
public final class ProtectedRecordCipher {
    private ProtectedRecordCipher() { }

    public interface Authorization {
        void authorize(Cipher cipher) throws Exception;
    }

    public static byte[] finish(Cipher cipher, byte[] context, byte[] value,
            int offset, int length, Authorization authorization) throws Exception {
        // Android Keystore can cache a pre-authentication AAD error until doFinal.
        // Do not submit AAD, plaintext or ciphertext before CryptoObject approval.
        if (authorization != null) authorization.authorize(cipher);
        cipher.updateAAD(context);
        return cipher.doFinal(value, offset, length);
    }
}
