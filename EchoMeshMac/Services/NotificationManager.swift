import Foundation
import UserNotifications

/// Manages macOS local user notifications for inbound messages and delivery events.
public final class NotificationManager: NSObject, @unchecked Sendable, UNUserNotificationCenterDelegate {
    public static let shared = NotificationManager()

    private let center = UNUserNotificationCenter.current()
    private var isAuthorized = false

    public override init() {
        super.init()
        center.delegate = self
    }

    /// Requests user notification permissions for alerts, sounds, and badges.
    public func requestAuthorization() async {
        do {
            let granted = try await center.requestAuthorization(options: [.alert, .sound, .badge])
            self.isAuthorized = granted
        } catch {
            print("[NotificationManager] Authorization request failed: \(error)")
        }
    }

    /// Displays a native macOS notification banner for an incoming message.
    public func showIncomingMessageNotification(from sender: String, content: String, chatId: String) {
        let notificationContent = UNMutableNotificationContent()
        notificationContent.title = "EchoMesh: \(sender)"
        notificationContent.subtitle = "New encrypted message"
        notificationContent.body = content
        notificationContent.sound = .default
        notificationContent.userInfo = ["chatId": chatId]

        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: notificationContent,
            trigger: nil // Deliver immediately
        )

        center.add(request) { error in
            if let error = error {
                print("[NotificationManager] Error posting notification: \(error)")
            }
        }
    }

    // MARK: - UNUserNotificationCenterDelegate

    public func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // Present banner and play sound even when app is key/front
        completionHandler([.banner, .sound, .badge])
    }
}
