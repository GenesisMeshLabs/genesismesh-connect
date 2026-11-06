package org.genesismesh.connect.authority

import android.app.Activity
import androidx.appcompat.app.AppCompatActivity
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.databind.JsonNode
import java.io.File
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/** Registered only by the opt-in qualification feature. Rust rejects every frontend invoke. */
@TauriPlugin
class OwnerQualificationPlugin(private val activity: Activity) : Plugin(activity) {
    init {
        require(activity.packageName == "org.genesismesh.connect.ownerqualification")
    }

    private fun args(invoke: Invoke, control: Boolean = false): JsonNode {
        require(invoke.getRawArgs().toByteArray(Charsets.UTF_8).size <= 128 * 1024)
        val value: JsonNode = jsonMapper().reader().with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .readTree(invoke.getRawArgs())
        val names = value.fieldNames().asSequence().toSet()
        require(value.isObject && names == if (control) setOf("schema", "session")
            else setOf("schema", "session", "sequence", "budget_ms", "request"))
        require(value["schema"].isIntegralNumber && value["schema"].canConvertToInt() && value["schema"].intValue() == 1)
        require(value["session"].isTextual && value["session"].textValue().length == 36)
        if (!control) {
            require(value["sequence"].isIntegralNumber && value["sequence"].canConvertToLong())
            require(value["budget_ms"].isIntegralNumber && value["budget_ms"].canConvertToInt())
            require(value["budget_ms"].intValue() in 1..180000)
            require(value["request"].isTextual && value["request"].textValue().toByteArray(Charsets.UTF_8).size <= 16 * 1024)
        }
        return value
    }

    @Command fun begin(invoke: Invoke) = submit(invoke, true)
    @Command fun exchange(invoke: Invoke) = submit(invoke, false)

    @Command fun inspectMembership(invoke: Invoke) {
        try {
            val value = args(invoke)
            require(value["request"].textValue() == "{\"op\":\"inspect_membership\"}" && value["budget_ms"].intValue() <= 30000)
            OwnerQualificationEngine.inspections.reserve(value["session"].textValue(), value["sequence"].longValue(), OwnerQualificationEngine.guard)
            val epoch = OwnerQualificationEngine.lifecycle.get()
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(value["budget_ms"].longValue())
            OwnerQualificationEngine.enqueue { OwnerQualificationEngine.inspect(activity, invoke, value, epoch, deadline) }
        } catch (_: Exception) { invoke.reject("A fresh read-only inspection session is required.") }
    }

    private fun submit(invoke: Invoke, begin: Boolean) {
        try {
            val value = args(invoke)
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(value["budget_ms"].longValue())
            OwnerQualificationEngine.enqueue {
                OwnerQualificationEngine.perform(activity, invoke, value, begin, deadline)
            }
        } catch (_: Exception) { invoke.reject("Native owner qualification request was refused.") }
    }

    @Command fun close(invoke: Invoke) {
        try {
            val value = args(invoke, true)
            val session = value["session"].textValue()
            require(OwnerQualificationEngine.guard.belongs(session))
            OwnerQualificationEngine.guard.stop() // Fence immediately, before waiting for work to settle.
            OwnerQualificationEngine.enqueue {
                try { OwnerQualificationEngine.close(); invoke.resolve() }
                catch (_: Exception) { invoke.reject("Authority shutdown remains unconfirmed. Restart the qualification process.") }
            }
        } catch (_: Exception) { invoke.reject("Native owner close was refused.") }
    }

    override fun onStop(activity: AppCompatActivity) { OwnerQualificationEngine.stopForLifecycle() }
    override fun onDestroy(activity: AppCompatActivity) { OwnerQualificationEngine.stopForLifecycle() }
}

/** Process-wide owner and bounded serial executor survive Activity recreation without replay. */
private object OwnerQualificationEngine {
    val guard = OwnerSessionGuard()
    val inspections = RecoveryInspectionGuard()
    val lifecycle = AtomicLong()
    private val worker = ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, ArrayBlockingQueue<Runnable>(4))
    private var owner: PyObject? = null
    private var module: PyObject? = null

    fun enqueue(action: () -> Unit) { worker.execute(action) }

    fun inspect(activity: Activity, invoke: Invoke, value: JsonNode, epoch: Long, deadline: Long) {
        try {
            require(!activity.isFinishing && !activity.isDestroyed && activity.hasWindowFocus()
                && lifecycle.get() == epoch && System.nanoTime() < deadline)
            val context = activity.applicationContext
            if (!Python.isStarted()) Python.start(AndroidPlatform(context))
            val inspector = Python.getInstance().getModule("android_connect_owner")
            val directory = File(context.noBackupFilesDir, "connect-owner-qualification").absolutePath
            // No RootKeyAuthorization, mutable owner/session or normal guard is reused.
            val result = inspector.callAttr("inspect_membership", directory, OwnerKeyVault(context)).toString()
            require(result.toByteArray(Charsets.UTF_8).size <= 4096 + 16)
            require(!activity.isFinishing && !activity.isDestroyed && activity.hasWindowFocus()
                && lifecycle.get() == epoch && System.nanoTime() < deadline)
            val reply = JSObject().put("schema", 1).put("session", value["session"].textValue())
                .put("sequence", value["sequence"].longValue()).put("reply", JSObject(result))
            invoke.resolve(JSObject(reply.toString()))
        } catch (_: Exception) { invoke.reject("Read-only inspection is unavailable. Existing state was preserved.") }
    }

    fun perform(activity: Activity, invoke: Invoke, value: JsonNode, begin: Boolean, deadline: Long) {
        val session = value["session"].textValue()
        val sequence = value["sequence"].longValue()
        try {
            require(!activity.isFinishing && !activity.isDestroyed && System.nanoTime() < deadline)
            if (begin) {
                require(value["request"].textValue() == "{\"op\":\"status\"}")
                guard.begin(session)
            }
            guard.reserve(session, sequence) // Durable core intents handle writes; this never permits replay.
            val result: String
            if (begin) {
                val context = activity.applicationContext
                if (!Python.isStarted()) Python.start(AndroidPlatform(context))
                module = Python.getInstance().getModule("android_connect_owner")
                val directory = File(context.noBackupFilesDir, "connect-owner-qualification").absolutePath
                val vault = OwnerKeyVault(context, RootKeyAuthorization(activity))
                owner = module!!.callAttr("begin", directory, vault)
                result = module!!.callAttr("handshake", owner).toString()
            } else {
                require(owner != null && module != null)
                result = module!!.callAttr("exchange", owner, value["request"].textValue()).toString()
            }
            require(result.toByteArray(Charsets.UTF_8).size <= 512 * 1024 - 256)
            require(guard.current(session) && System.nanoTime() < deadline)
            val outcome = JSObject(result)
            require(outcome.length() == 1 && (outcome.has("ok") || outcome.has("error")))
            if (outcome.has("error")) guard.stop()
            val reply = JSObject().put("schema", 1).put("session", session)
                .put("sequence", sequence).put("reply", outcome)
            invoke.resolve(JSObject(reply.toString()))
        } catch (_: Exception) {
            guard.stop()
            invoke.reject("Native owner operation is unconfirmed. Existing state was preserved; it will not be repeated.")
        }
    }

    fun stopForLifecycle() {
        lifecycle.incrementAndGet()
        guard.stop()
        try { enqueue { try { close() } catch (_: Exception) { /* Retain unsettled owner; never recreate. */ } } }
        catch (_: Exception) { /* Session is fenced even if the queue is full. */ }
    }

    fun close() {
        owner?.callAttr("close") // If handlers have not settled, retain the owner and its lock.
        owner?.close()
        owner = null
        module = null
    }
}
