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

class PickArgs: Decodable { let media: Bool }

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
  @objc public func pick(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(PickArgs.self)
    DispatchQueue.main.async {
      guard self.pendingPick == nil, let presenter = self.manager.viewController else {
        invoke.reject("Finish choosing the current file first"); return
      }
      self.pendingPick = invoke
      if args.media {
        var configuration = PHPickerConfiguration()
        configuration.selectionLimit = 1
        configuration.filter = .any(of: [.images, .videos])
        let picker = PHPickerViewController(configuration: configuration)
        picker.delegate = self
        presenter.present(picker, animated: true)
      } else {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.item], asCopy: false)
        picker.allowsMultipleSelection = false
        picker.delegate = self
        presenter.present(picker, animated: true)
      }
    }
  }
  func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
    pendingPick?.resolve([:]); pendingPick = nil
  }
  func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
    guard let invoke = pendingPick, let source = urls.first else { return }
    DispatchQueue.global(qos: .userInitiated).async { self.prepareSelected(source, invoke: invoke) }
  }
  func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
    picker.dismiss(animated: true)
    guard let invoke = pendingPick else { return }
    guard let item = results.first?.itemProvider, let type = item.registeredTypeIdentifiers.first else {
      invoke.resolve([:]); pendingPick = nil; return
    }
    item.loadFileRepresentation(forTypeIdentifier: type) { source, error in
      guard let source = source else {
        invoke.reject(error?.localizedDescription ?? "Could not read the selected photo or video")
        DispatchQueue.main.async { self.pendingPick = nil }
        return
      }
      // The provider URL expires when this callback returns. Finish the copy
      // here, not in a newly dispatched task that might run after it expires.
      self.prepareSelected(source, invoke: invoke)
    }
  }
  private func prepareSelected(_ source: URL, invoke: Invoke) {
      let access = source.startAccessingSecurityScopedResource()
      defer {
        if access { source.stopAccessingSecurityScopedResource() }
        DispatchQueue.main.async { self.pendingPick = nil }
      }
      var target: URL?
      do {
        let root = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("connect-picked", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        target = root.appendingPathComponent(UUID().uuidString + ".bin")
        let sourceSize = try source.resourceValues(forKeys: [.fileSizeKey]).fileSize
        func room(_ remaining: UInt64) throws {
          let stats = try FileManager.default.attributesOfFileSystem(forPath: root.path)
          let free = (stats[.systemFreeSize] as? NSNumber)?.uint64Value ?? 0
          let total = (stats[.systemSize] as? NSNumber)?.uint64Value ?? 0
          let reserve = min(max(total / 20, 64 * 1024 * 1024), 1024 * 1024 * 1024)
          if free < reserve || remaining > free - reserve {
            throw NSError(domain: "Connect", code: 1, userInfo: [NSLocalizedDescriptionKey: "Not enough free storage to prepare this file"])
          }
        }
        try room(UInt64(max(sourceSize ?? 8 * 1024 * 1024, 0)))
        FileManager.default.createFile(atPath: target!.path, contents: nil)
        let input = try FileHandle(forReadingFrom: source)
        let output = try FileHandle(forWritingTo: target!)
        defer { try? input.close(); try? output.close() }
        var total: UInt64 = 0
        var checked: UInt64 = 0
        while let data = try input.read(upToCount: 64 * 1024), !data.isEmpty {
          total += UInt64(data.count)
          if total > 9007199254740991 { throw NSError(domain: "Connect", code: 2, userInfo: [NSLocalizedDescriptionKey: "File is too large"]) }
          if checked == 0 || checked >= 8 * 1024 * 1024 {
            let expected = UInt64(max(sourceSize ?? 0, 0))
            try room(expected >= total ? expected - total + UInt64(data.count) : 8 * 1024 * 1024)
            checked = 0
          }
          try output.write(contentsOf: data)
          checked += UInt64(data.count)
        }
        if let expected = sourceSize, total != UInt64(expected) { throw NSError(domain: "Connect", code: 3, userInfo: [NSLocalizedDescriptionKey: "The file changed while preparing it"]) }
        try output.synchronize()
        invoke.resolve(["path": target!.path, "name": source.lastPathComponent])
      } catch {
        if let target = target { try? FileManager.default.removeItem(at: target) }
        invoke.reject(error.localizedDescription)
      }
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
