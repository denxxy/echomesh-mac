import AppKit
import Foundation

public final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var mainWindow: NSWindow?

    public func applicationDidFinishLaunching(_ notification: Notification) {
        // Request local notification permissions
        Task {
            await NotificationManager.shared.requestAuthorization()
        }

        // Hook into newly opened windows to set delegate for intercepting close button
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(windowDidBecomeKeyNotification(_:)),
            name: NSWindow.didBecomeKeyNotification,
            object: nil
        )
    }

    @objc public func windowDidBecomeKeyNotification(_ notification: Notification) {
        guard let window = notification.object as? NSWindow else { return }
        // Exclude system status bar / menu windows, capture main document/app window
        if window.canBecomeMain && mainWindow == nil {
            mainWindow = window
            window.delegate = self
        }
    }

    // MARK: - NSWindowDelegate

    /// Intercepts clicking the red close button on the main window.
    /// Instead of closing or terminating, the window orders out and the app remains running in the MenuBar.
    public func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    // MARK: - Reopening from Dock or Spotlight

    public func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            if let window = mainWindow ?? NSApp.windows.first(where: { $0.canBecomeMain }) {
                window.makeKeyAndOrderFront(self)
            }
        }
        return true
    }

    // MARK: - Application Termination

    public func applicationWillTerminate(_ notification: Notification) {
        // Synchronously trigger graceful shutdown of the Rust engine and Tokio runtime
        let shutdownSemaphore = DispatchSemaphore(value: 0)
        Task {
            await CoreBridgeService.shared.shutdown()
            shutdownSemaphore.signal()
        }
        _ = shutdownSemaphore.wait(timeout: .now() + 1.0)
    }
}
