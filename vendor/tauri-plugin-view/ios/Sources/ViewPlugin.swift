import Tauri
import WebKit
import UniformTypeIdentifiers
import PhotosUI
import SafariServices
class WebArgs: Decodable { let url: String }

class ViewArgs: Decodable {
  let path: String?
  let share: Bool?
}

class PickArgs: Decodable { let media: Bool; let multiple: Bool }

class ViewPlugin: Plugin, UIDocumentPickerDelegate, PHPickerViewControllerDelegate {
  @objc public func web(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(WebArgs.self)
    guard let url = URL(string: args.url), url.scheme == "http", url.host == "127.0.0.1", url.port != nil else {
      invoke.reject("Invalid local web app address"); return
    }
    DispatchQueue.main.async {
      guard let presenter = self.manager.viewController else { invoke.reject("Could not open web app"); return }
      presenter.present(SFSafariViewController(url: url), animated: true)
      invoke.resolve([:])
    }
  }
  private var pendingPick: Invoke?
  private var pendingMultiple = false
  @objc public func pick(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(PickArgs.self)
    DispatchQueue.main.async {
      guard self.pendingPick == nil, let presenter = self.manager.viewController else {
        invoke.reject("Finish choosing the current files first"); return
      }
      self.pendingPick = invoke
      self.pendingMultiple = args.multiple
      if args.media {
        var configuration = PHPickerConfiguration()
        configuration.selectionLimit = args.multiple ? 100 : 1
        configuration.selection = .ordered
        configuration.preferredAssetRepresentationMode = .current
        configuration.filter = .any(of: [.images, .videos])
        let picker = PHPickerViewController(configuration: configuration)
        picker.delegate = self
        presenter.present(picker, animated: true)
      } else {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.item], asCopy: false)
        picker.allowsMultipleSelection = args.multiple
        picker.delegate = self
        presenter.present(picker, animated: true)
      }
    }
  }
  private func finishPick(_ files: [[String: String]], error: Error? = nil) {
    if error != nil {
      for file in files { if let path = file["path"] { try? FileManager.default.removeItem(atPath: path) } }
    }
    DispatchQueue.main.async {
      guard let invoke = self.pendingPick else { return }
      self.pendingPick = nil
      if let error = error { invoke.reject(error.localizedDescription) }
      else { invoke.resolve(["files": files]) }
    }
  }
  private func selectionError(_ text: String) -> NSError {
    return NSError(domain: "Connect", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
  }
  func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { finishPick([]) }
  func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
    guard pendingPick != nil else { return }
    guard urls.count <= (pendingMultiple ? 100 : 1) else { finishPick([], error: selectionError("Choose up to 100 files at a time")); return }
    DispatchQueue.global(qos: .userInitiated).async {
      var files: [[String: String]] = []
      do {
        for source in urls { files.append(try self.prepareSelected(source, name: source.lastPathComponent)) }
        self.finishPick(files)
      } catch { self.finishPick(files, error: error) }
    }
  }
  func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
    picker.dismiss(animated: true)
    guard pendingPick != nil else { return }
    guard results.count <= (pendingMultiple ? 100 : 1) else { finishPick([], error: selectionError("Choose up to 100 photos or videos at a time")); return }
    var files: [[String: String]] = []
    // Load one representation at a time to bound memory and disk pressure. The
    // provider URL expires on callback return, so copy inside that callback.
    func next(_ index: Int) {
      if index == results.count { self.finishPick(files); return }
      let item = results[index].itemProvider
      guard let identifier = item.registeredTypeIdentifiers.first(where: {
        guard let type = UTType($0) else { return false }
        return type.conforms(to: .image) || type.conforms(to: .movie)
      }), let type = UTType(identifier) else {
        self.finishPick(files, error: self.selectionError("This photo or video has no readable file representation")); return
      }
      item.loadFileRepresentation(forTypeIdentifier: identifier) { source, error in
        guard let source = source else {
          self.finishPick(files, error: error ?? self.selectionError("Could not download this photo or video. Check your connection and try again.")); return
        }
        do {
          var name = item.suggestedName ?? source.lastPathComponent
          if (name as NSString).pathExtension.isEmpty {
            let ext = source.pathExtension.isEmpty ? (type.preferredFilenameExtension ?? "") : source.pathExtension
            if !ext.isEmpty { name += "." + ext }
          }
          files.append(try self.prepareSelected(source, name: name))
          next(index + 1)
        } catch { self.finishPick(files, error: error) }
      }
    }
    next(0)
  }
  private func prepareSelected(_ source: URL, name: String) throws -> [String: String] {
    let access = source.startAccessingSecurityScopedResource()
    defer { if access { source.stopAccessingSecurityScopedResource() } }
    // Tauri's app_cache_dir is Library/Caches/<bundle identifier> on iOS.
    // Keep this contract aligned; Library/Caches alone fails Rust's containment check.
    guard let identifier = Bundle.main.bundleIdentifier else { throw selectionError("Missing app storage identity") }
    let root = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
      .appendingPathComponent(identifier, isDirectory: true).appendingPathComponent("connect-picked", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let target = root.appendingPathComponent(UUID().uuidString + ".bin")
    do {
      let sourceSize = try source.resourceValues(forKeys: [.fileSizeKey]).fileSize
      func room(_ remaining: UInt64) throws {
        let stats = try FileManager.default.attributesOfFileSystem(forPath: root.path)
        let free = (stats[.systemFreeSize] as? NSNumber)?.uint64Value ?? 0
        let total = (stats[.systemSize] as? NSNumber)?.uint64Value ?? 0
        let reserve = min(max(total / 20, 64 * 1024 * 1024), 1024 * 1024 * 1024)
        if free < reserve || remaining > free - reserve { throw self.selectionError("Not enough free storage to prepare these files") }
      }
      try room(UInt64(max(sourceSize ?? 8 * 1024 * 1024, 0)))
      guard FileManager.default.createFile(atPath: target.path, contents: nil) else { throw selectionError("Could not prepare this file") }
      let input = try FileHandle(forReadingFrom: source)
      defer { try? input.close() }
      let output = try FileHandle(forWritingTo: target)
      defer { try? output.close() }
      var total: UInt64 = 0
      var checked: UInt64 = 0
      while let data = try input.read(upToCount: 64 * 1024), !data.isEmpty {
        total += UInt64(data.count)
        if total > 9007199254740991 { throw selectionError("File is too large") }
        if checked == 0 || checked >= 8 * 1024 * 1024 {
          let expected = UInt64(max(sourceSize ?? 0, 0))
          try room(expected >= total ? expected - total + UInt64(data.count) : 8 * 1024 * 1024)
          checked = 0
        }
        try output.write(contentsOf: data)
        checked += UInt64(data.count)
      }
      if let expected = sourceSize, total != UInt64(expected) { throw selectionError("The file changed while preparing it") }
      try output.synchronize()
      return ["path": target.path, "name": name]
    } catch { try? FileManager.default.removeItem(at: target); throw error }
  }

  @objc public func view(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ViewArgs.self)

    DispatchQueue.main.async {
      if args.share == true {
        guard let presenter = self.manager.viewController else {
          invoke.reject("Document presentation is unavailable")
          return
        }
        let activity = UIActivityViewController(activityItems: [URL(fileURLWithPath: args.path ?? "")], applicationActivities: nil)
        if let popover = activity.popoverPresentationController {
          popover.sourceView = presenter.view
          popover.sourceRect = CGRect(x: presenter.view.bounds.midX, y: presenter.view.bounds.midY, width: 0, height: 0)
          popover.permittedArrowDirections = []
        }
        presenter.present(activity, animated: true)
        invoke.resolve(["value": "OK"])
        return
      }
      let controller = Controller()
      controller.setUrl(URL(fileURLWithPath: args.path ?? ""))
      self.manager.viewController?.addChild(controller)
      self.manager.viewController?.view.addSubview(controller.view)
      invoke.resolve(["value": "OK"])
    }
  }
}

@_cdecl("init_plugin_view")
public func initPlugin() -> Plugin {
  return ViewPlugin()
}

class Controller: UIViewController, UIDocumentInteractionControllerDelegate {
  var url: URL!
  var controller: UIDocumentInteractionController!

  func setUrl(_ url: URL) {
    self.url = url
  }

  override func viewDidLoad() {
    super.viewDidLoad()
    controller = UIDocumentInteractionController(url: self.url)
    controller.delegate = self
    if !controller.presentPreview(animated: true) {
      controller.presentOpenInMenu(from: self.view.bounds, in: self.view, animated: true)
    }
  }

  func documentInteractionControllerDidEndPreview(_ controller: UIDocumentInteractionController) {
    self.view.removeFromSuperview()
    self.removeFromParent()
  }

  func documentInteractionControllerDidDismissOpenInMenu(
    _ controller: UIDocumentInteractionController
  ) {
    self.view.removeFromSuperview()
    self.removeFromParent()
  }

  func documentInteractionControllerViewControllerForPreview(
    _ controller: UIDocumentInteractionController
  ) -> UIViewController {
    return self
  }
}
