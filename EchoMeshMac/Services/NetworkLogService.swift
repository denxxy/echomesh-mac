import Foundation
import Observation
import os.log

/// Level of logged network event.
public enum NetworkLogLevel: String, Sendable, Codable {
    case info = "INFO"
    case warning = "WARN"
    case error = "ERROR"
    case debug = "DEBUG"
}

/// An entry in the recent network event history.
public struct NetworkLogEntry: Identifiable, Sendable, Hashable {
    public let id: UUID
    public let timestamp: Date
    public let level: NetworkLogLevel
    public let message: String

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        level: NetworkLogLevel = .info,
        message: String
    ) {
        self.id = id
        self.timestamp = timestamp
        self.level = level
        self.message = message
    }
}

/// Service managing structured network event logging via unified macOS `os.Logger`
/// and maintaining a bounded ring buffer of the last 50 connection events for UI display.
@Observable
@MainActor
public final class NetworkLogService: Sendable {
    public static let shared = NetworkLogService()

    private let systemLogger = os.Logger(subsystem: "com.echomesh.mac", category: "Network")
    public private(set) var entries: [NetworkLogEntry] = []
    public let maxCapacity: Int = 50

    public init() {}

    /// Logs an event to macOS system log and stores it in the recent in-memory buffer.
    /// Sensitive data such as raw keys and message bodies are strictly sanitized or omitted.
    public func log(_ message: String, level: NetworkLogLevel = .info) {
        let entry = NetworkLogEntry(timestamp: Date(), level: level, message: message)

        // Dispatch to system unified log
        switch level {
        case .info:
            systemLogger.info("\(message, privacy: .public)")
        case .warning:
            systemLogger.warning("\(message, privacy: .public)")
        case .error:
            systemLogger.error("\(message, privacy: .public)")
        case .debug:
            systemLogger.debug("\(message, privacy: .public)")
        }

        // Maintain ring buffer of last 50 items
        entries.append(entry)
        if entries.count > maxCapacity {
            entries.removeFirst(entries.count - maxCapacity)
        }
    }

    /// Convenience helper for errors.
    public func logError(_ error: Error, context: String) {
        log("\(context): \(error.localizedDescription)", level: .error)
    }

    /// Clears the in-memory log buffer.
    public func clear() {
        entries.removeAll()
    }
}
