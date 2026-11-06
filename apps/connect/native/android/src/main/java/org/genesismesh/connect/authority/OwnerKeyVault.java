package org.genesismesh.connect.authority;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyInfo;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/** Separate non-exportable authority/member wrapping keys. No identity/key reset API. */
public final class OwnerKeyVault {
    private static final String ROOT = "org.genesismesh.connect.authority.root.v1";
    private static final String OWNER = "org.genesismesh.connect.authority.owner.v1";
    private static final String MEMBER = "org.genesismesh.connect.authority.member.v1";
    private static final int MAX = 32768;
    private final KeyguardManager keyguard;
    private final KeyStore keys;
    private final RootKeyAuthorization rootAuthorization;

    public OwnerKeyVault(Context context) throws Exception {
        this(context, null);
    }

    public OwnerKeyVault(Context context, RootKeyAuthorization rootAuthorization) throws Exception {
        this.rootAuthorization = rootAuthorization;
        keyguard = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        keys = KeyStore.getInstance("AndroidKeyStore");
        keys.load(null);
    }

    public synchronized void ready() {
        String status = readiness();
        if (!"ready".equals(status)) throw new IllegalStateException(status);
    }

    public synchronized String readiness() {
        // Android 15 fixes known unlocked-device key lifecycle issues in older
        // releases. Client Join is unaffected by this owner-profile minimum.
        if (Build.VERSION.SDK_INT < 35 || keyguard == null) return "unsupported_device";
        if (!keyguard.isDeviceSecure()) return "secure_screen_lock_required";
        if (keyguard.isDeviceLocked()) return "device_unlock_required";
        return "ready";
    }

    public synchronized void create() throws Exception {
        ready();
        if (keys.containsAlias(ROOT) || keys.containsAlias(OWNER) || keys.containsAlias(MEMBER)) {
            throw new IllegalStateException("Existing authority custody must not be replaced.");
        }
        generate(ROOT, true);
        generate(OWNER, false);
        generate(MEMBER, false); // A partial failure stays blocked; never delete/recreate existing entries.
    }

    /**
     * Remove the wrapping keys of a creation that sealed no record, so it can
     * be tried again. The embedded owner calls this only when this attempt made
     * the keys and its storage holds nothing but the attempt's own marker.
     */
    public synchronized void discardUnsealed() throws Exception {
        ready();
        for (String alias : new String[] {ROOT, OWNER, MEMBER}) {
            if (keys.containsAlias(alias)) keys.deleteEntry(alias);
        }
    }

    /** Fixed-alias metadata only. Never infer empty custody from missing files. */
    public synchronized boolean hasCustody() throws Exception {
        ready();
        return keys.containsAlias(ROOT) || keys.containsAlias(OWNER) || keys.containsAlias(MEMBER);
    }

    /** Metadata/key handle only; opening a network does not authenticate or decrypt its root. */
    public synchronized void require_root_custody() throws Exception { key(ROOT); }

    private void generate(String alias, boolean root) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec.Builder spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true).setUnlockedDeviceRequired(true);
        if (root) spec.setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
        generator.init(spec.build());
        generator.generateKey();
    }

    private SecretKey key(String alias) throws Exception {
        ready();
        SecretKey key = (SecretKey) keys.getKey(alias, null);
        if (key == null || key.getEncoded() != null) {
            throw new IllegalStateException("Existing protected authority key is unavailable.");
        }
        if (ROOT.equals(alias)) {
            KeyInfo info = (KeyInfo) SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                .getKeySpec(key, KeyInfo.class);
            if (!RootKeyPolicy.isPerUse(info.isUserAuthenticationRequired(), info.getUserAuthenticationValidityDurationSeconds(),
                    info.getUserAuthenticationType(), KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL)) {
                throw new IllegalStateException("Root custody requires per-operation device authentication.");
            }
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
            byte[] iv = cipher.getIV();
            if (iv.length != 12) throw new IllegalStateException("Unexpected protected record format.");
            byte[] ciphertext = ProtectedRecordCipher.finish(cipher, context(role, instance), value, 0, value.length,
                ROOT.equals(alias) ? operation -> authorizeRoot(operation, "Protect network root key") : null);
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
        return ProtectedRecordCipher.finish(cipher, context(role, instance), value, 13, value.length - 13,
            ROOT.equals(alias) ? operation -> authorizeRoot(operation, "Use network root key") : null);
    }

    private void authorizeRoot(Cipher cipher, String action) throws Exception {
        if (rootAuthorization == null) throw new IllegalStateException("Root use requires native user authentication.");
        rootAuthorization.authorize(cipher, action);
        ready();
    }

    /** Bounded nonsecret diagnostics; no key bytes, aliases or platform error text. */
    public synchronized String rootPolicyStatus() {
        try {
            ready();
            if (!keys.containsAlias(ROOT)) return "missing";
            key(ROOT);
            return "per_use";
        } catch (Exception ignored) { return "unavailable_or_unqualified"; }
    }

    public String rootAuthenticationStatus() {
        return rootAuthorization == null ? "unavailable" : rootAuthorization.status();
    }

    /** Fixed-alias policy metadata for the isolated developer qualification report. */
    public synchronized String rootPolicyMetadata() {
        org.json.JSONObject result = new org.json.JSONObject();
        try {
            result.put("readiness", readiness());
            ready();
            if (!keys.containsAlias(ROOT)) return result.put("present", false).toString();
            SecretKey root = (SecretKey) keys.getKey(ROOT, null);
            KeyInfo info = (KeyInfo) SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                .getKeySpec(root, KeyInfo.class);
            return result.put("present", true).put("authentication_required", info.isUserAuthenticationRequired())
                .put("validity_seconds", info.getUserAuthenticationValidityDurationSeconds())
                .put("authenticator_types", info.getUserAuthenticationType()).toString();
        } catch (Exception ignored) { return "{\"status\":\"unavailable\"}"; }
    }

    public synchronized byte[] seal_root(String instance, byte[] value) throws Exception { return seal(ROOT, "Root", instance, value); }
    // Native ceremony primitive only; no root-export or generic signing IPC exists.
    public synchronized byte[] open_root(String instance, byte[] value) throws Exception { return open(ROOT, "Root", instance, value); }
    public synchronized byte[] seal_owner(String instance, byte[] value) throws Exception { return seal(OWNER, "Owner", instance, value); }
    public synchronized byte[] seal_member(String instance, byte[] value) throws Exception { return seal(MEMBER, "Member", instance, value); }
    public synchronized byte[] open_owner(String instance, byte[] value) throws Exception { return open(OWNER, "Owner", instance, value); }
    public synchronized byte[] open_member(String instance, byte[] value) throws Exception { return open(MEMBER, "Member", instance, value); }
}
