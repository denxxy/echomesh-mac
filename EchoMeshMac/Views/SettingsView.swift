import SwiftUI
import AppKit

public struct SettingsView: View {
    var appState: AppState
    @Environment(\.dismiss) private var dismiss

    // Form editing state
    @State private var editingEndpointId: UUID? = nil
    @State private var formName: String = ""
    @State private var formHost: String = "77.81.5.109"
    @State private var formPortString: String = "8443"
    @State private var formKeyBase64: String = ""

    // Health Check state
    @State private var isHealthChecking: Bool = false
    @State private var healthCheckLatency: UInt32? = nil
    @State private var healthCheckError: String? = nil

    // Copy state
    @State private var copiedBase58: Bool = false
    @State private var copiedHex: Bool = false
    @State private var copiedLogs: Bool = false

    public init(appState: AppState) {
        self.appState = appState
    }

    public var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("EchoMesh Настройки")
                    .font(.title3.bold())
                Spacer()
                Button(action: { dismiss() }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                        .font(.title3)
                }
                .buttonStyle(.plain)
            }
            .padding(16)
            .background(.ultraThinMaterial)

            Divider()

            TabView {
                // MARK: - Tab 1: Сеть и Релеи
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        // Section: Active Relays
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                Text("Сохраненные релей-ноды")
                                    .font(.headline)
                                Spacer()
                                Button(action: resetFormForNew) {
                                    Label("Новая нода", systemImage: "plus.circle")
                                        .font(.caption)
                                }
                            }

                            ForEach(appState.configManager.endpoints) { endpoint in
                                relayRow(endpoint: endpoint)
                            }
                        }

                        Divider()

                        // Section: Add / Edit Node Form
                        VStack(alignment: .leading, spacing: 14) {
                            HStack {
                                Text(editingEndpointId == nil ? "Добавить релей-ноду" : "Редактировать релей-ноду")
                                    .font(.headline)
                                Spacer()
                                if editingEndpointId != nil {
                                    Button("Отмена", action: resetFormForNew)
                                        .font(.caption)
                                }
                            }

                            // Name
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Название:")
                                    .font(.caption.bold())
                                TextField("Например: Primary Relay", text: $formName)
                                    .textFieldStyle(.roundedBorder)
                            }

                            // Host & Port
                            HStack(spacing: 12) {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Host / IP:")
                                        .font(.caption.bold())
                                    TextField("77.81.5.109", text: $formHost)
                                        .textFieldStyle(.roundedBorder)
                                }
                                .frame(maxWidth: .infinity)

                                VStack(alignment: .leading, spacing: 4) {
                                    Text("Порт:")
                                        .font(.caption.bold())
                                    TextField("8443", text: $formPortString)
                                        .textFieldStyle(.roundedBorder)
                                        .frame(width: 80)
                                }
                            }

                            // Server Public Key (Base64)
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text("Server Public Key (Noise static Base64, 32 байта):")
                                        .font(.caption.bold())
                                    Spacer()
                                    Button(action: pasteKeyFromClipboard) {
                                        Label("Вставить", systemImage: "doc.on.clipboard")
                                            .font(.caption2)
                                    }
                                    .buttonStyle(.borderless)
                                }

                                TextField("Base64 ключ сервера (например: Vh4...=)", text: $formKeyBase64)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(.body, design: .monospaced))

                                keyValidationHintView
                            }

                            // Action buttons: Save, Health Check
                            HStack(spacing: 12) {
                                Button(action: saveFormEndpoint) {
                                    Label(editingEndpointId == nil ? "Сохранить ноду" : "Обновить", systemImage: "square.and.arrow.down")
                                }
                                .buttonStyle(.borderedProminent)

                                Button(action: runHealthCheckForForm) {
                                    if isHealthChecking {
                                        ProgressView()
                                            .controlSize(.small)
                                            .padding(.trailing, 4)
                                    }
                                    Label("Проверить соединение", systemImage: "network.badge.shield.half.filled")
                                }
                                .disabled(isHealthChecking || formHost.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                                Spacer()
                            }

                            // Health Check Feedback Banner
                            if let latency = healthCheckLatency {
                                HStack(spacing: 8) {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundColor(.green)
                                    Text("Успешно: Узел доступен, задержка RTT = \(latency) мс")
                                        .font(.callout.bold())
                                        .foregroundColor(.green)
                                }
                                .padding(10)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.green.opacity(0.12))
                                .cornerRadius(8)
                            } else if let errorMsg = healthCheckError {
                                HStack(alignment: .top, spacing: 8) {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundColor(.red)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Ошибка проверки:")
                                            .font(.caption.bold())
                                            .foregroundColor(.red)
                                        Text(errorMsg)
                                            .font(.caption)
                                            .foregroundColor(.red)
                                            .textSelection(.enabled)
                                    }
                                }
                                .padding(10)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(Color.red.opacity(0.12))
                                .cornerRadius(8)
                            }
                        }
                    }
                    .padding(20)
                }
                .tabItem {
                    Label("Сеть и Релеи", systemImage: "network")
                }

                // MARK: - Tab 2: Журнал сети (Network Logs)
                VStack(spacing: 0) {
                    HStack {
                        Text("Последние \(appState.logService.entries.count) событий сети")
                            .font(.headline)
                        Spacer()
                        Button("Скопировать") {
                            copyLogsToClipboard()
                        }
                        .font(.caption)

                        Button("Очистить") {
                            appState.logService.clear()
                        }
                        .font(.caption)
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 12)
                    .padding(.bottom, 8)

                    Divider()

                    if appState.logService.entries.isEmpty {
                        VStack(spacing: 8) {
                            Image(systemName: "text.badge.checkmark")
                                .font(.system(size: 32))
                                .foregroundColor(.secondary)
                            Text("Журнал пуст")
                                .font(.callout)
                                .foregroundColor(.secondary)
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                    } else {
                        List(appState.logService.entries.reversed()) { entry in
                            HStack(alignment: .top, spacing: 8) {
                                Text(entry.timestamp, style: .time)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(.secondary)
                                    .frame(width: 65, alignment: .leading)

                                Text(entry.level.rawValue)
                                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                                    .padding(.horizontal, 4)
                                    .padding(.vertical, 1)
                                    .background(logBadgeColor(entry.level).opacity(0.15))
                                    .foregroundColor(logBadgeColor(entry.level))
                                    .cornerRadius(4)

                                Text(entry.message)
                                    .font(.system(size: 11))
                                    .textSelection(.enabled)

                                Spacer()
                            }
                            .padding(.vertical, 2)
                        }
                        .listStyle(.inset)
                    }
                }
                .tabItem {
                    Label("Журнал сети", systemImage: "list.bullet.rectangle")
                }

                // MARK: - Tab 3: Identity Key
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        HStack(spacing: 8) {
                            Image(systemName: "lock.shield.fill")
                                .foregroundColor(.green)
                                .font(.title2)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("Apple Keychain Защита Активна")
                                    .font(.headline)
                                Text("Секретный сид Ed25519 зашифрован и защищен kSecAttrAccessibleAfterFirstUnlock.")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                        .padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.green.opacity(0.1))
                        .cornerRadius(8)

                        if let identity = appState.identity {
                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text("Ключ идентификации (Base58):")
                                        .font(.subheadline.bold())
                                    Spacer()
                                    Button(action: {
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general.setString(identity.publicKeyBase58, forType: .string)
                                        copiedBase58 = true
                                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                            copiedBase58 = false
                                        }
                                    }) {
                                        Label(copiedBase58 ? "Скопировано!" : "Копировать Base58", systemImage: copiedBase58 ? "checkmark" : "doc.on.doc")
                                            .font(.caption)
                                    }
                                }

                                Text(identity.publicKeyBase58)
                                    .font(.system(size: 11, design: .monospaced))
                                    .padding(8)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(Color(NSColor.controlBackgroundColor))
                                    .cornerRadius(6)
                                    .textSelection(.enabled)
                            }

                            VStack(alignment: .leading, spacing: 6) {
                                HStack {
                                    Text("Ключ идентификации (Hex):")
                                        .font(.subheadline.bold())
                                    Spacer()
                                    Button(action: {
                                        NSPasteboard.general.clearContents()
                                        NSPasteboard.general.setString(identity.publicKeyHex, forType: .string)
                                        copiedHex = true
                                        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                            copiedHex = false
                                        }
                                    }) {
                                        Label(copiedHex ? "Скопировано!" : "Копировать Hex", systemImage: copiedHex ? "checkmark" : "doc.on.doc")
                                            .font(.caption)
                                    }
                                }

                                Text(identity.publicKeyHex)
                                    .font(.system(size: 11, design: .monospaced))
                                    .padding(8)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(Color(NSColor.controlBackgroundColor))
                                    .cornerRadius(6)
                                    .textSelection(.enabled)
                            }
                        } else {
                            ProgressView("Чтение идентификатора из Keychain...")
                        }
                    }
                    .padding(20)
                }
                .tabItem {
                    Label("Identity", systemImage: "person.badge.key")
                }
            }

            Divider()

            // Footer
            HStack {
                Spacer()
                Button("Закрыть") {
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding(12)
            .background(.ultraThinMaterial)
        }
        .frame(width: 580, height: 500)
    }

    // MARK: - Row View for Relay Endpoint
    @ViewBuilder
    private func relayRow(endpoint: RelayEndpoint) -> some View {
        let isActive = appState.configManager.activeEndpointId == endpoint.id
        HStack(spacing: 12) {
            Button(action: {
                appState.switchEndpoint(endpoint)
            }) {
                Image(systemName: isActive ? "largecircle.fill.circle" : "circle")
                    .foregroundColor(isActive ? .accentColor : .secondary)
                    .font(.title3)
            }
            .buttonStyle(.plain)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(endpoint.name)
                        .font(.system(size: 13, weight: .semibold))
                    if endpoint.isDefault {
                        Text("По умолчанию")
                            .font(.system(size: 9, weight: .bold))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Color.blue.opacity(0.15))
                            .foregroundColor(.blue)
                            .cornerRadius(4)
                    }
                }

                Text(endpoint.formattedAddress)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary)

                if endpoint.publicKeyBase64.isEmpty {
                    Text("Публичный ключ не задан")
                        .font(.system(size: 10))
                        .foregroundColor(.orange)
                }
            }

            Spacer()

            // Edit button
            Button(action: { startEditing(endpoint: endpoint) }) {
                Image(systemName: "pencil")
                    .foregroundColor(.secondary)
            }
            .buttonStyle(.plain)
            .help("Редактировать")

            // Delete button (can't delete if only one left)
            if appState.configManager.endpoints.count > 1 {
                Button(action: { appState.configManager.delete(id: endpoint.id) }) {
                    Image(systemName: "trash")
                        .foregroundColor(.red.opacity(0.8))
                }
                .buttonStyle(.plain)
                .help("Удалить")
            }
        }
        .padding(10)
        .background(Color(NSColor.controlBackgroundColor).opacity(isActive ? 0.9 : 0.4))
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(isActive ? Color.accentColor.opacity(0.4) : Color.clear, lineWidth: 1)
        )
    }

    // MARK: - Validation Hint View
    @ViewBuilder
    private var keyValidationHintView: some View {
        let trimmed = formKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            Text("Поле открыто для ввода публичного ключа сервера (32 байта Base64).")
                .font(.caption2)
                .foregroundColor(.secondary)
        } else if let data = Data(base64Encoded: trimmed) {
            if data.count == 32 {
                Label("Корректный 32-байтовый ключ Base64", systemImage: "checkmark.circle.fill")
                    .font(.caption2)
                    .foregroundColor(.green)
            } else {
                Label("Некорректный размер: \(data.count) байт (требуется ровно 32 байта)", systemImage: "exclamationmark.circle.fill")
                    .font(.caption2)
                    .foregroundColor(.red)
            }
        } else {
            Label("Недопустимая строка Base64", systemImage: "xmark.octagon.fill")
                .font(.caption2)
                .foregroundColor(.red)
        }
    }

    // MARK: - Form Actions
    private func resetFormForNew() {
        editingEndpointId = nil
        formName = "Custom Relay"
        formHost = "77.81.5.109"
        formPortString = "8443"
        formKeyBase64 = ""
        healthCheckLatency = nil
        healthCheckError = nil
    }

    private func startEditing(endpoint: RelayEndpoint) {
        editingEndpointId = endpoint.id
        formName = endpoint.name
        formHost = endpoint.host
        formPortString = String(endpoint.port)
        formKeyBase64 = endpoint.publicKeyBase64
        healthCheckLatency = nil
        healthCheckError = nil
    }

    private func saveFormEndpoint() {
        let port = UInt16(formPortString.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 8443
        let name = formName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Primary Relay" : formName
        let host = formHost.trimmingCharacters(in: .whitespacesAndNewlines)

        if let id = editingEndpointId {
            var updated = RelayEndpoint(
                id: id,
                name: name,
                host: host,
                port: port,
                publicKeyBase64: formKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            // Preserve default flag if it was default
            if let existing = appState.configManager.endpoints.first(where: { $0.id == id }) {
                updated.isDefault = existing.isDefault
            }
            appState.configManager.update(endpoint: updated)
        } else {
            let newEndpoint = RelayEndpoint(
                name: name,
                host: host,
                port: port,
                publicKeyBase64: formKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines),
                isDefault: appState.configManager.endpoints.isEmpty
            )
            appState.configManager.add(endpoint: newEndpoint)
        }
        resetFormForNew()
    }

    private func pasteKeyFromClipboard() {
        if let string = NSPasteboard.general.string(forType: .string) {
            formKeyBase64 = string.trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    private func runHealthCheckForForm() {
        let port = UInt16(formPortString.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 8443
        let tempEndpoint = RelayEndpoint(
            name: formName,
            host: formHost.trimmingCharacters(in: .whitespacesAndNewlines),
            port: port,
            publicKeyBase64: formKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines)
        )

        isHealthChecking = true
        healthCheckLatency = nil
        healthCheckError = nil

        Task {
            let result = await appState.healthCheck(endpoint: tempEndpoint)
            isHealthChecking = false
            switch result {
            case .success(let ms):
                healthCheckLatency = ms
            case .failure(let err):
                healthCheckError = err.message
            }
        }
    }

    private func copyLogsToClipboard() {
        let lines = appState.logService.entries.map {
            "[\($0.timestamp.formatted(date: .omitted, time: .standard))] [\($0.level.rawValue)] \($0.message)"
        }.joined(separator: "\n")
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines, forType: .string)
        copiedLogs = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            copiedLogs = false
        }
    }

    private func logBadgeColor(_ level: NetworkLogLevel) -> Color {
        switch level {
        case .info: return .blue
        case .warning: return .orange
        case .error: return .red
        case .debug: return .purple
        }
    }
}
