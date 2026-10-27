import Tauri
import WebKit

class ViewArgs: Decodable {
  let path: String?
  let share: Bool?
}

class ViewPlugin: Plugin {
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
