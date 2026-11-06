package org.genesismesh.connect.authority;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class ProtectedRecordCipherTest {
    // Model Android's cached AAD failure: a later auth success cannot repair it.
    private static final class PerUseSpi extends CipherSpi {
        boolean authenticated, cachedFailure, aad, finished;
        @Override protected void engineSetMode(String mode) { }
        @Override protected void engineSetPadding(String padding) { }
        @Override protected int engineGetBlockSize() { return 16; }
        @Override protected int engineGetOutputSize(int length) { return length; }
        @Override protected byte[] engineGetIV() { return new byte[12]; }
        @Override protected AlgorithmParameters engineGetParameters() { return null; }
        @Override protected void engineInit(int mode, Key key, SecureRandom random) { }
        @Override protected void engineInit(int mode, Key key, AlgorithmParameterSpec params, SecureRandom random) { }
        @Override protected void engineInit(int mode, Key key, AlgorithmParameters params, SecureRandom random) { }
        @Override protected void engineUpdateAAD(byte[] value, int offset, int length) {
            if (!authenticated) cachedFailure = true;
            aad = true;
        }
        @Override protected byte[] engineUpdate(byte[] value, int offset, int length) { throw new AssertionError(); }
        @Override protected int engineUpdate(byte[] value, int offset, int length, byte[] output, int start) { throw new AssertionError(); }
        @Override protected byte[] engineDoFinal(byte[] value, int offset, int length) throws IllegalBlockSizeException {
            finished = true;
            if (cachedFailure || !authenticated || !aad) throw new IllegalBlockSizeException();
            return Arrays.copyOfRange(value, offset, offset + length);
        }
        @Override protected int engineDoFinal(byte[] value, int offset, int length, byte[] output, int start) { throw new AssertionError(); }
    }
    private static final class FixtureCipher extends Cipher {
        FixtureCipher(PerUseSpi spi) { super(spi, new Provider("Fixture", 1.0, "host-only") { }, "Fixture"); }
    }
    public static void main(String[] args) throws Exception {
        byte[] context = "Root:test-instance".getBytes("UTF-8"), value = {1, 2, 3};
        SecretKey key = new SecretKeySpec(new byte[32], "AES");
        PerUseSpi old = new PerUseSpi();
        Cipher oldCipher = new FixtureCipher(old); oldCipher.init(Cipher.ENCRYPT_MODE, key);
        oldCipher.updateAAD(context); old.authenticated = true;
        try { oldCipher.doFinal(value); throw new AssertionError("Old ordering did not reproduce cached failure"); }
        catch (IllegalBlockSizeException expected) { }
        for (int mode : new int[]{Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE}) {
            PerUseSpi spi = new PerUseSpi(); Cipher cipher = new FixtureCipher(spi); cipher.init(mode, key);
            byte[] result = ProtectedRecordCipher.finish(cipher, context, value, 0, value.length, operation -> {
                if (operation != cipher || spi.aad || spi.finished) throw new AssertionError("Wrong operation/order");
                spi.authenticated = true;
            });
            if (!Arrays.equals(result, value) || !spi.finished) throw new AssertionError("Authorized operation failed");
        }
        PerUseSpi denied = new PerUseSpi(); Cipher refused = new FixtureCipher(denied); refused.init(Cipher.ENCRYPT_MODE, key);
        try {
            ProtectedRecordCipher.finish(refused, context, value, 0, value.length, operation -> { throw new SecurityException(); });
            throw new AssertionError("Denied authorization continued");
        } catch (SecurityException expected) { }
        if (denied.aad || denied.finished) throw new AssertionError("Cipher used after denied authorization");
        // Real AES/GCM keeps the context authenticated for daily records too.
        Cipher encrypt = Cipher.getInstance("AES/GCM/NoPadding"); encrypt.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = ProtectedRecordCipher.finish(encrypt, context, value, 0, value.length, null);
        Cipher decrypt = Cipher.getInstance("AES/GCM/NoPadding");
        decrypt.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, encrypt.getIV()));
        if (!Arrays.equals(value, ProtectedRecordCipher.finish(decrypt, context, ciphertext, 0, ciphertext.length, null)))
            throw new AssertionError("Daily custody roundtrip failed");
        Cipher wrong = Cipher.getInstance("AES/GCM/NoPadding");
        wrong.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, encrypt.getIV()));
        try {
            ProtectedRecordCipher.finish(wrong, new byte[]{0}, ciphertext, 0, ciphertext.length, null);
            throw new AssertionError("Foreign context accepted");
        } catch (AEADBadTagException expected) { }
    }
}
