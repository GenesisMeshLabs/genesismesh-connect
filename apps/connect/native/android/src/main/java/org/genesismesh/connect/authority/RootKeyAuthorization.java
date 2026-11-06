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
    private volatile String outcome = "not_requested";

    public RootKeyAuthorization(Activity activity) { this.activity = new WeakReference<>(activity); }
    public String status() { return outcome; }

    public void authorize(Cipher cipher, String action) throws Exception {
        outcome = "preparing";
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
                outcome = "foreground_required";
                completed.countDown();
                return;
            }
            try {
                outcome = "authentication_pending";
                new BiometricPrompt.Builder(host).setTitle(action)
                    .setSubtitle("Genesis Mesh · confirm this one root-key operation")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                        | BiometricManager.Authenticators.DEVICE_CREDENTIAL).build()
                    .authenticate(new BiometricPrompt.CryptoObject(cipher), cancellation, host.getMainExecutor(),
                        new BiometricPrompt.AuthenticationCallback() {
                            @Override public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                                BiometricPrompt.CryptoObject crypto = result.getCryptoObject();
                                if (active.get() && crypto != null && crypto.getCipher() == cipher) {
                                    accepted.set(true);
                                    outcome = "authenticated";
                                } else outcome = "cipher_mismatch";
                                completed.countDown();
                            }
                            @Override public void onAuthenticationError(int code, CharSequence ignored) {
                                if (active.get()) outcome = "authentication_error";
                                completed.countDown();
                            }
                        });
            } catch (RuntimeException ignored) { outcome = "prompt_unavailable"; completed.countDown(); }
        });
        boolean authorized = false;
        try {
            if (!completed.await(120, TimeUnit.SECONDS)) {
                outcome = "timed_out";
                throw new IllegalStateException("Root-key authentication was not completed. Existing state was preserved.");
            }
            if (!accepted.get()) {
                throw new IllegalStateException("Root-key authentication was not completed. Existing state was preserved.");
            }
            authorized = true;
        } finally {
            active.set(false);
            if (!authorized) cancellation.cancel();
        }
    }
}
