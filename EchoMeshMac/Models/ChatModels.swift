import Foundation

// MARK: - Data Hex Extensions

public extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    var shortHex: String {
        let hex = hexString
        if hex.count <= 10 {
            return "0x" + hex
        }
        let prefix = hex.prefix(4)
        let suffix = hex.suffix(4)
        return "0x\(prefix)...\(suffix)"
    }
}

// MARK: - ConversationSummary Extensions

extension ConversationSummary: Identifiable {
    public var id: String {
        peerId.hexString
    }

    public var peerIdHex: String {
        peerId.hexString
    }

    public var shortPeerId: String {
        peerId.shortHex
    }

    public var isEchoNode: Bool {
        peerId == Data(repeating: 0xEE, count: 32)
    }

    public var displayTitle: String {
        let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            return trimmed
        }
        return shortPeerId
    }

    public var initials: String {
        if isEchoNode {
            return "⚡️"
        }
        let words = displayTitle.split(separator: " ")
        if words.count >= 2 {
            let first = words[0].prefix(1)
            let second = words[1].prefix(1)
            return "\(first)\(second)".uppercased()
        } else if let firstWord = words.first, !firstWord.isEmpty {
            return String(firstWord.prefix(2)).uppercased()
        }
        return "P"
    }

    public var formattedTime: String {
        guard lastTimestamp > 0 else { return "" }
        let date = Date(timeIntervalSince1970: Double(lastTimestamp) / 1000.0)
        let calendar = Calendar.current
        let formatter = DateFormatter()

        if calendar.isDateInToday(date) {
            formatter.dateFormat = "HH:mm"
        } else if calendar.isDateInYesterday(date) {
            return "Вчера"
        } else {
            formatter.dateFormat = "dd.MM"
        }
        return formatter.string(from: date)
    }
}

// MARK: - MessageRecord Extensions

extension MessageRecord: Identifiable {
    public var conversationPeerIdHex: String {
        conversationPeerId.hexString
    }

    public var senderPeerIdHex: String {
        senderPeerId.hexString
    }

    public var date: Date {
        Date(timeIntervalSince1970: Double(timestamp) / 1000.0)
    }

    public var formattedTime: String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        return formatter.string(from: date)
    }

    public var isEchoSender: Bool {
        senderPeerId == Data(repeating: 0xEE, count: 32)
    }
}

// MARK: - Key Validation Utility

public enum KeyValidator {
    public struct ValidationResult: Equatable, Sendable {
        public let isValid: Bool
        public let hexString: String?
        public let byteCount: Int
        public let errorMessage: String?

        public static func valid(hex: String, bytes: Int = 32) -> ValidationResult {
            ValidationResult(isValid: true, hexString: hex, byteCount: bytes, errorMessage: nil)
        }

        public static func invalid(reason: String, byteCount: Int = 0) -> ValidationResult {
            ValidationResult(isValid: false, hexString: nil, byteCount: byteCount, errorMessage: reason)
        }
    }

    /// Validates an input string as a 32-byte public key (Hex or Base64).
    public static func validate(_ rawInput: String) -> ValidationResult {
        let trimmed = rawInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .invalid(reason: "Введите публичный ключ контакта")
        }

        // 1. Try Hex (with optional 0x prefix)
        let cleanHex = trimmed.hasPrefix("0x") || trimmed.hasPrefix("0X")
            ? String(trimmed.dropFirst(2))
            : trimmed

        if cleanHex.count == 64 && cleanHex.range(of: "^[0-9a-fA-F]{64}$", options: .regularExpression) != nil {
            return .valid(hex: cleanHex.lowercased(), bytes: 32)
        }

        // If hex characters but wrong count
        if cleanHex.range(of: "^[0-9a-fA-F]+$", options: .regularExpression) != nil {
            let bytes = cleanHex.count / 2
            return .invalid(
                reason: "Неверная длина Hex: получено \(bytes) байт (\(cleanHex.count) симв.), ожидается 32 байта (64 симв.)",
                byteCount: bytes
            )
        }

        // 2. Try Base64
        if let base64Data = Data(base64Encoded: trimmed) {
            if base64Data.count == 32 {
                return .valid(hex: base64Data.hexString, bytes: 32)
            } else {
                return .invalid(
                    reason: "Неверная длина Base64: получено \(base64Data.count) байт, ожидается 32 байта",
                    byteCount: base64Data.count
                )
            }
        }

        return .invalid(reason: "Неверный формат ключа: поддерживается 64-символьный Hex или 32-байтный Base64")
    }
}
