package org.genesismesh.connect.authoritycheck;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.widget.ScrollView;
import android.widget.TextView;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;
import org.json.JSONObject;
import org.json.JSONArray;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import org.genesismesh.connect.authority.OwnerKeyVault;

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
        status.setText("Genesis Mesh\n\nChecking the network engine on this phone…");
        root.addView(status);
        setContentView(root);
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
                        new OwnerKeyVault(getApplicationContext())).toString());
                    report.put("owner_check", owner);
                    if (!"passed".equals(owner.optString("status"))) {
                        report.put("status", "failed").put("stage", owner.optString("stage", "Owner custody"));
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
            JSONArray ownerChecks = owner.optJSONArray("checks");
            if (ownerChecks != null) for (int i = 0; i < ownerChecks.length(); i++) {
                text.append(ownerChecks.optJSONObject(i).optString("name")).append(": Passed\n");
            }
        }
        text.append("\nDevelopment runtime check. Network creation is not enabled by this test.");
        status.setText(text.toString());
    }
}
