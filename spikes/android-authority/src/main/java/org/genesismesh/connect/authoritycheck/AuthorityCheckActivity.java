package org.genesismesh.connect.authoritycheck;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Button;
import android.widget.LinearLayout;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;
import org.json.JSONObject;
import org.json.JSONArray;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import org.genesismesh.connect.authority.OwnerKeyVault;
import org.genesismesh.connect.authority.RootKeyAuthorization;

public final class AuthorityCheckActivity extends Activity {
    private static final EngineCheckRunner<JSONObject> ENGINE =
        new EngineCheckRunner<>(Executors.newSingleThreadExecutor());
    private TextView status;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        ScrollView root = new ScrollView(this);
        root.setBackgroundColor(Color.rgb(16, 32, 23));
        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        root.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(padding, padding + insets.getSystemWindowInsetTop(), padding,
                padding + insets.getSystemWindowInsetBottom());
            return insets;
        });
        status = new TextView(this);
        status.setTextColor(Color.rgb(214, 239, 197));
        status.setTextSize(19);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.addView(status);
        root.addView(content);
        setContentView(root);
        if ("org.genesismesh.connect.authoritycheck.rootcheck".equals(getPackageName())) {
            status.setText("Genesis Mesh\n\nRoot-key check\n\nKeep this phone unlocked and stay in this app. "
                + "When you tap Start check, Android will ask you to protect the test network's root key. "
                + "Confirm with your screen lock or fingerprint on this phone.\n\n"
                + "This separate test does not change your Connect network.\n\n");
            Button start = new Button(this);
            start.setText("Start check");
            content.addView(start);
            start.setOnClickListener(view -> {
                start.setEnabled(false);
                start.setVisibility(android.view.View.GONE);
                runCheck();
            });
        } else {
            runCheck();
        }
    }

    private void runCheck() {
        status.setText("Genesis Mesh\n\nChecking the network engine…\n\nStay in this app. "
            + "If Android asks to protect the root key, confirm on this phone.");
        try { ENGINE.start(() -> {
            JSONObject report;
            String stage = "Python startup";
            try {
                if (!Python.isStarted()) Python.start(new AndroidPlatform(getApplicationContext()));
                report = new JSONObject(Python.getInstance().getModule("authority_check")
                    .callAttr("run", BuildConfig.CORE_VERSION).toString());
                if ("passed".equals(report.optString("status"))) {
                    stage = "Protected owner custody";
                    JSONObject owner = new JSONObject(Python.getInstance().getModule("owner_check").callAttr("run",
                        BuildConfig.CORE_VERSION, new java.io.File(getNoBackupFilesDir(), "authority-check").getAbsolutePath(),
                        new OwnerKeyVault(getApplicationContext(), new RootKeyAuthorization(this))).toString());
                    report.put("owner_check", owner);
                    if (!"passed".equals(owner.optString("status"))) {
                        report.put("status", "blocked".equals(owner.optString("status")) ? "blocked" : "failed")
                            .put("stage", owner.optString("stage", "Owner custody"));
                    }
                }
                report.put("source_commit", BuildConfig.SOURCE_COMMIT);
                report.put("device_api", android.os.Build.VERSION.SDK_INT);
            } catch (Throwable error) {
                report = new JSONObject();
                try { report.put("status", "failed").put("stage", stage)
                    .put("exception_type", error.getClass().getSimpleName()).put("source_commit", BuildConfig.SOURCE_COMMIT); }
                catch (Exception ignored) { }
            }
            return report;
        }, new EngineCheckRunner.Listener<JSONObject>() {
            @Override public void started(String runId) {
                try { save(new JSONObject().put("status", "running").put("run_id", runId)
                    .put("source_commit", BuildConfig.SOURCE_COMMIT)); }
                catch (Exception error) { throw new IllegalStateException("Could not save the test status."); }
            }

            @Override public void completed(String runId, JSONObject result) {
                try { result.put("run_id", runId); save(result); }
                catch (Exception error) {
                    runOnUiThread(() -> ENGINE.publishIfActive(runId,
                        () -> status.setText("Could not save the test result.")));
                    return;
                }
                runOnUiThread(() -> ENGINE.publishIfActive(runId, () -> show(result)));
            }
        }); } catch (RuntimeException error) {
            status.setText("Could not start the test or save its status.");
        }
    }

    private void save(JSONObject report) throws Exception {
        try (java.io.FileOutputStream stream = openFileOutput("authority-runtime-report.json", MODE_PRIVATE)) {
            stream.write(report.toString(2).getBytes(StandardCharsets.UTF_8));
        }
    }

    private void show(JSONObject report) {
        if (isFinishing() || isDestroyed()) return;
        boolean passed = "passed".equals(report.optString("status"));
        StringBuilder text = new StringBuilder("Genesis Mesh\n\n");
        text.append(passed ? "Engine check passed\n\n" : "Engine check needs attention\n\n");
        JSONArray checks = report.optJSONArray("checks");
        if (checks != null) for (int i = 0; i < checks.length(); i++) {
            JSONObject check = checks.optJSONObject(i);
            text.append(check.optString("name")).append(": ")
                .append(check.optBoolean("passed") ? "Passed" : "Needs attention").append("\n");
        }
        if (!passed) text.append("\nCheck: ").append(report.optString("stage", "startup")).append("\n");
        JSONObject owner = report.optJSONObject("owner_check");
        if (owner != null) {
            if ("timed_out".equals(owner.optString("root_authentication"))) {
                text.append("\nAndroid's confirmation timed out. No root-key use was approved. ")
                    .append("The unfinished test setup has been preserved for inspection.\n");
            }
            if ("secure_screen_lock_required".equals(owner.optString("readiness"))) {
                text.append("\nThis owner profile requires a PIN, password or pattern on the phone. ")
                    .append("Set one locally in Settings, then reopen this check.\n");
            } else if ("device_unlock_required".equals(owner.optString("readiness"))) {
                text.append("\nUnlock this phone, then reopen this check.\n");
            }
            JSONArray ownerChecks = owner.optJSONArray("checks");
            if (ownerChecks != null) for (int i = 0; i < ownerChecks.length(); i++) {
                text.append(ownerChecks.optJSONObject(i).optString("name")).append(": Passed\n");
            }
        }
        text.append("\nDevelopment runtime check. Network creation is not enabled by this test.");
        status.setText(text.toString());
    }
}
