package org.genesismesh.connect.authority;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/** Separate non-exportable authority/member wrapping keys. No identity/key reset API. */
public final class OwnerKeyVault {
    private static final String OWNER = "org.genesismesh.connect.authority.owner.v1";
    private static final String MEMBER = "org.genesismesh.connect.authority.member.v1";
    private static final int MAX = 32768;
    private final KeyguardManager keyguard;
    private final KeyStore keys;

    public OwnerKeyVault(Context context) throws Exception {
        keyguard = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        keys = KeyStore.getInstance("AndroidKeyStore");
        keys.load(null);
    }

    public synchronized void ready() {
        String status = readiness();
        if (!"ready".equals(status)) throw new IllegalStateException(status);
    }

    public synchronized String readiness() {
        if (Build.VERSION.SDK_INT < 30 || keyguard == null) return "unsupported_device";
        if (!keyguard.isDeviceSecure()) return "secure_screen_lock_required";
        if (keyguard.isDeviceLocked()) return "device_unlock_required";
        return "ready";
    }

    public synchronized void create() throws Exception {
        ready();
        if (keys.containsAlias(OWNER) || keys.containsAlias(MEMBER)) {
            throw new IllegalStateException("Existing authority custody must not be replaced.");
        }
        generate(OWNER);
        generate(MEMBER); // A partial failure remains blocked; never delete/recreate existing entries.
    }

    /** Fixed-alias metadata only. Never infer empty custody from missing files. */
    public synchronized boolean hasCustody() throws Exception {
        ready();
        return keys.containsAlias(OWNER) || keys.containsAlias(MEMBER);
    }

    private void generate(String alias) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true).setUnlockedDeviceRequired(true).build());
        generator.generateKey();
    }

    private SecretKey key(String alias) throws Exception {
        ready();
        SecretKey key = (SecretKey) keys.getKey(alias, null);
        if (key == null || key.getEncoded() != null) {
            throw new IllegalStateException("Existing protected authority key is unavailable.");
        }
        return key;
    }

    private byte[] context(String role, String instance) {
        if (!UUID.fromString(instance).toString().equals(instance)) throw new IllegalArgumentException("Invalid network identity.");
        return ("GenesisMesh.Connect.AndroidAuthority." + role + ".v1\0" + instance).getBytes(StandardCharsets.UTF_8);
    }

    private byte[] seal(String alias, String role, String instance, byte[] value) throws Exception {
        if (value == null || value.length == 0 || value.length > MAX) throw new IllegalArgumentException("Invalid authority record size.");
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key(alias));
            cipher.updateAAD(context(role, instance));
            byte[] iv = cipher.getIV();
            if (iv.length != 12) throw new IllegalStateException("Unexpected protected record format.");
            byte[] ciphertext = cipher.doFinal(value);
            byte[] envelope = new byte[13 + ciphertext.length];
            envelope[0] = 1;
            System.arraycopy(iv, 0, envelope, 1, 12);
            System.arraycopy(ciphertext, 0, envelope, 13, ciphertext.length);
            return envelope;
        } finally { Arrays.fill(value, (byte) 0); }
    }

    private byte[] open(String alias, String role, String instance, byte[] value) throws Exception {
        if (value == null || value.length < 30 || value.length > MAX + 29 || value[0] != 1) {
            throw new IllegalArgumentException("Invalid protected authority record.");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(alias), new GCMParameterSpec(128, value, 1, 12));
        cipher.updateAAD(context(role, instance));
        return cipher.doFinal(value, 13, value.length - 13);
    }

    public synchronized byte[] seal_owner(String instance, byte[] value) throws Exception { return seal(OWNER, "Owner", instance, value); }
    public synchronized byte[] seal_member(String instance, byte[] value) throws Exception { return seal(MEMBER, "Member", instance, value); }
    public synchronized byte[] open_owner(String instance, byte[] value) throws Exception { return open(OWNER, "Owner", instance, value); }
    public synchronized byte[] open_member(String instance, byte[] value) throws Exception { return open(MEMBER, "Member", instance, value); }
}
