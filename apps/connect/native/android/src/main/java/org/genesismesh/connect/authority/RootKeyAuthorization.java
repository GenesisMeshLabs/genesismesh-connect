package org.genesismesh.connect.authority;

import android.app.Activity;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.CancellationSignal;
import android.os.Looper;
import java.lang.ref.WeakReference;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.Cipher;

/** A fresh system prompt authorizes the exact Keystore operation, never a Boolean permission. */
public final class RootKeyAuthorization {
    private final WeakReference<Activity> activity;

    public RootKeyAuthorization(Activity activity) { this.activity = new WeakReference<>(activity); }

    public void authorize(Cipher cipher, String action) throws Exception {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Root authentication must not block the main thread.");
        }
        Activity host = activity.get();
        if (host == null || host.isFinishing() || host.isDestroyed()) {
            throw new IllegalStateException("Open Connect to authorize this root operation.");
        }
        CancellationSignal cancellation = new CancellationSignal();
        CountDownLatch completed = new CountDownLatch(1);
        AtomicBoolean accepted = new AtomicBoolean(false);
        AtomicBoolean active = new AtomicBoolean(true);
        host.runOnUiThread(() -> {
            if (!active.get() || host.isFinishing() || host.isDestroyed() || !host.hasWindowFocus()) {
                completed.countDown();
                return;
            }
            try {
                new BiometricPrompt.Builder(host).setTitle(action)
                    .setSubtitle("Genesis Mesh · confirm this one root-key operation")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                        | BiometricManager.Authenticators.DEVICE_CREDENTIAL).build()
                    .authenticate(new BiometricPrompt.CryptoObject(cipher), cancellation, host.getMainExecutor(),
                        new BiometricPrompt.AuthenticationCallback() {
                            @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                                BiometricPrompt.CryptoObject crypto = result.getCryptoObject();
                                if (active.get() && crypto != null && crypto.getCipher() == cipher) accepted.set(true);
                                completed.countDown();
                            }
                            @Override public void onAuthenticationError(int code, CharSequence ignored) { completed.countDown(); }
                        });
            } catch (RuntimeException ignored) { completed.countDown(); }
        });
        boolean authorized = false;
        try {
            if (!completed.await(120, TimeUnit.SECONDS) || !accepted.get()) {
                throw new IllegalStateException("Root-key authentication was not completed. Existing state was preserved.");
            }
            authorized = true;
        } finally {
            active.set(false);
            if (!authorized) cancellation.cancel();
        }
    }
}
