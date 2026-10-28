package dev.ecmel.view

import android.app.Activity
import android.content.Intent
import android.provider.OpenableColumns
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import java.util.concurrent.atomic.AtomicBoolean
import androidx.core.content.FileProvider
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.File

@InvokeArg
class ViewArgs {
  var path: String? = null
  var share: Boolean = false
}

@InvokeArg
class PickArgs { var media: Boolean = false; var multiple: Boolean = false }

@InvokeArg
class WebArgs { var url: String = "" }

@TauriPlugin
class ViewPlugin(private val activity: Activity) : Plugin(activity) {
  @Command
  fun web(invoke: Invoke) {
    val args = invoke.parseArgs(WebArgs::class.java)
    val uri = android.net.Uri.parse(args.url)
    if (uri.scheme != "http" || uri.host != "127.0.0.1" || uri.port <= 0) { invoke.reject("Invalid local web app address"); return }
    activity.runOnUiThread {
      // Separate native WebView: no Tauri bridge or JS interfaces. Keep the
      // hosting activity foreground while the local TCP connection runs.
      val web = android.webkit.WebView(activity)
      web.settings.javaScriptEnabled = true
      web.settings.allowFileAccess = false
      web.settings.allowContentAccess = false
      web.settings.domStorageEnabled = true
      web.webViewClient = object : android.webkit.WebViewClient() {
        override fun shouldOverrideUrlLoading(view: android.webkit.WebView, request: android.webkit.WebResourceRequest): Boolean {
          return request.url.scheme != "http" || request.url.host != "127.0.0.1" || request.url.port != uri.port
        }
      }
      val dialog = android.app.Dialog(activity)
      val layout = android.widget.LinearLayout(activity).apply { orientation = android.widget.LinearLayout.VERTICAL }
      val close = android.widget.Button(activity).apply { text = "Back to Connect"; setOnClickListener { dialog.dismiss() } }
      layout.addView(close); layout.addView(web, android.widget.LinearLayout.LayoutParams(-1, 0, 1f))
      dialog.setContentView(layout)
      dialog.setOnDismissListener { web.stopLoading(); web.destroy() }
      dialog.show(); dialog.window?.setLayout(-1, -1)
      web.loadUrl(args.url); invoke.resolve(JSObject())
    }
  }
  private val picking = AtomicBoolean(false)

  @Command
  fun pick(invoke: Invoke) {
    if (!picking.compareAndSet(false, true)) { invoke.reject("Finish choosing the current file first"); return }
    try {
      val args = invoke.parseArgs(PickArgs::class.java)
      val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
      intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, args.multiple)
      if (args.media) intent.putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("image/*", "video/*"))
      startActivityForResult(invoke, intent, "picked")
    } catch (e: Exception) { picking.set(false); invoke.reject("Could not open the file picker") }
  }

  @ActivityCallback
  fun picked(invoke: Invoke, result: ActivityResult) {
    if (result.resultCode != Activity.RESULT_OK || result.data == null) {
      picking.set(false); invoke.resolve(JSObject().put("files", org.json.JSONArray())); return
    }
    val uris = mutableListOf<android.net.Uri>()
    result.data?.clipData?.let { clip -> for (i in 0 until clip.itemCount) uris.add(clip.getItemAt(i).uri) }
    if (uris.isEmpty()) result.data?.data?.let { uris.add(it) }
    if (uris.size > 100) { picking.set(false); invoke.reject("Choose up to 100 files at a time"); return }
    // Providers can return non-seekable streams. Make one private bounded-memory
    // copy, with the provider's display name, before Rust hashes and resumes it.
    Thread {
      val copies = mutableListOf<File>()
      try {
        val files = org.json.JSONArray()
        for (uri in uris.distinct()) {
        var copy: File? = null
        val resolver = activity.contentResolver
        var name = "Shared file"
        var size: Long? = null
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use {
          if (it.moveToFirst()) {
            val n = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            val z = it.getColumnIndex(OpenableColumns.SIZE)
            if (n >= 0 && !it.isNull(n)) name = it.getString(n)
            if (z >= 0 && !it.isNull(z) && it.getLong(z) >= 0) size = it.getLong(z)
          }
        }
        val root = File(activity.cacheDir, "connect-picked").apply { mkdirs() }
        fun room(remaining: Long) {
          val reserve = (root.totalSpace / 20).coerceIn(64L * 1024 * 1024, 1024L * 1024 * 1024)
          check(remaining <= (root.usableSpace - reserve).coerceAtLeast(0)) { "Not enough free storage to prepare this file" }
        }
        room(size ?: 8L * 1024 * 1024)
        copy = File.createTempFile("picked-", ".bin", root)
        copies.add(copy!!)
        resolver.openInputStream(uri)?.use { input ->
          copy!!.outputStream().use { output ->
            val buffer = ByteArray(64 * 1024)
            var total = 0L
            var sinceCheck = 0L
            while (true) {
              val count = input.read(buffer)
              if (count < 0) break
              if (count == 0) continue
              total += count
              check(total <= 9007199254740991L) { "File is too large" }
              if (sinceCheck == 0L || sinceCheck >= 8L * 1024 * 1024) {
                room(size?.let { (it - total + count).coerceAtLeast(count.toLong()) } ?: 8L * 1024 * 1024)
                sinceCheck = 0
              }
              output.write(buffer, 0, count)
              sinceCheck += count
            }
            if (size != null) check(total == size) { "The file changed while preparing it" }
          }
        } ?: error("Could not read the selected file")
        files.put(JSObject().put("path", copy!!.absolutePath).put("name", name))
        }
        invoke.resolve(JSObject().put("files", files))
      } catch (e: Exception) {
        copies.forEach { it.delete() }
        invoke.reject(e.message ?: "Could not prepare the selected file")
      } finally { picking.set(false) }
    }.start()
  }

  @Command
  fun view(invoke: Invoke) {
    val args = invoke.parseArgs(ViewArgs::class.java)
    val context = activity.applicationContext
    val path = args.path ?: ""

    val uri = FileProvider.getUriForFile(
      context,
      context.packageName + ".fileprovider",
      File(path)
    )

    context.grantUriPermission(
      context.packageName,
      uri,
      Intent.FLAG_GRANT_READ_URI_PERMISSION
    )

    val mime = context.contentResolver.getType(uri)

    if (args.share) {
      val intent = Intent(Intent.ACTION_SEND)
        .setType(mime ?: "application/octet-stream")
        .putExtra(Intent.EXTRA_STREAM, uri)
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
      activity.startActivity(Intent.createChooser(intent, "Save or share file"))
      invoke.resolve(JSObject().put("value", "OK"))
      return
    }

    try {
      val intent = Intent(Intent.ACTION_QUICK_VIEW)
        .setDataAndType(uri, mime)
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      context.startActivity(intent)
    } catch (e: Exception) {
      try {
        val intent = Intent(Intent.ACTION_VIEW)
          .setDataAndType(uri, mime)
          .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
          .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
      } catch (e: Exception) {
        val intent = Intent(Intent.ACTION_SEND)
          .setType(mime ?: "application/octet-stream")
          .putExtra(Intent.EXTRA_STREAM, uri)
          .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
          .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
      }
    }

    val ret = JSObject()
    ret.put("value", "OK")
    invoke.resolve(ret)
  }
}
