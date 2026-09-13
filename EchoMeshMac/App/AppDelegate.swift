import AppKit
import Foundation
import os.log

public final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate {
    private var mainWindow: NSWindow?
    private let securityLogger = os.Logger(subsystem: "com.echomesh.mac", category: "Security")

    public func applicationDidFinishLaunching(_ notification: Notification) {
        verifyAppSandboxNetworkAccess()

        Task {
            await NotificationManager.shared.requestAuthorization()
        }

        // Initialize the shared Rust identity/storage first, then start the
        // CoreBluetooth bearer. BLE only receives the public identity and opaque
        // E2EE direct packets from the core.
        Task {
            do {
                try await CoreBridgeService.shared.start()
                await MainActor.run {
                    BLETransportService.shared.start()
                }
            } catch {
                securityLogger.error("Unable to initialize EchoMesh direct transport")
            }
        }

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(windowDidBecomeKeyNotification(_:)),
            name: NSWindow.didBecomeKeyNotification,
            object: nil
        )
    }

    private func verifyAppSandboxNetworkAccess() {
        let isSandboxed = ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil
        if isSandboxed {
            securityLogger.info("[App Sandbox] Active container detected")
            securityLogger.info("[App Sandbox] Outgoing network entitlement expected")
        } else {
            securityLogger.info("[App Sandbox] Running outside sandbox (developer/debug mode)")
        }
    }

    @objc public func windowDidBecomeKeyNotification(_ notification: Notification) {
        guard let window = notification.object as? NSWindow else { return }
        if window.canBecomeMain && mainWindow == nil {
            mainWindow = window
            window.delegate = self
        }
    }

    public func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    public func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            if let window = mainWindow ?? NSApp.windows.first(where: { $0.canBecomeMain }) {
                window.makeKeyAndOrderFront(self)
            }
        }
        return true
    }

    public func applicationWillTerminate(_ notification: Notification) {
        BLETransportService.shared.stop()
        let shutdownSemaphore = DispatchSemaphore(value: 0)
        Task {
            await CoreBridgeService.shared.shutdown()
            shutdownSemaphore.signal()
        }
        _ = shutdownSemaphore.wait(timeout: .now() + 1.0)
    }
}
