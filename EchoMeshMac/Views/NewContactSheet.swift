import SwiftUI

public struct NewContactSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Bindable var chatListVM: ChatListViewModel

    @State private var name: String = ""
    @State private var keyInput: String = ""
    @State private var isSubmitting: Bool = false
    @State private var submissionError: String? = nil

    private static let echoBotKeyHex = String(repeating: "ee", count: 32)

    public init(chatListVM: ChatListViewModel) {
        self.chatListVM = chatListVM
    }

    private var validation: KeyValidator.ValidationResult {
        KeyValidator.validate(keyInput)
    }

    public var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("Новый контакт")
                    .font(.headline)
                Spacer()
                Button(action: { dismiss() }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.secondary)
                        .font(.system(size: 16))
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 20)
            .padding(.top, 18)
            .padding(.bottom, 12)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Quick Action: Add Echo Bot
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Тестовый эхо-сервер")
                                .font(.system(size: 12, weight: .semibold))
                            Text("Встроенный лупбек-узел релея [0xEE; 32]")
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Button("Добавить Echo-бота") {
                            fillEchoBot()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                    .padding(12)
                    .background(Color.accentColor.opacity(0.08))
                    .cornerRadius(8)

                    // Contact Name Field
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Имя контакта")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundColor(.secondary)

                        TextField("Например: Alice или Tokyo Relay", text: $name)
                            .textFieldStyle(.roundedBorder)
                    }

                    // Public Key Input
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text("Noise Public Key")
                                .font(.system(size: 12, weight: .medium))
                                .foregroundColor(.secondary)
                            Spacer()
                            Text("Hex (64 симв.) или Base64 (32 байта)")
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }

                        TextField("Вставьте 32-байтовый ключ (Hex или Base64)", text: $keyInput, axis: .vertical)
                            .lineLimit(2...3)
                            .font(.system(size: 11, design: .monospaced))
                            .textFieldStyle(.roundedBorder)
                    }

                    // Validation Feedback Banner
                    if !keyInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        if validation.isValid, let hex = validation.hexString {
                            HStack(spacing: 8) {
                                Image(systemName: "checkmark.seal.fill")
                                    .foregroundColor(.green)
                                    .font(.system(size: 14))
                                VStack(alignment: .leading, spacing: 1) {
                                    Text("Ключ валиден (32 байта)")
                                        .font(.system(size: 11, weight: .semibold))
                                        .foregroundColor(.green)
                                    Text("0x\(hex.prefix(8))...\(hex.suffix(8))")
                                        .font(.system(size: 10, design: .monospaced))
                                        .foregroundColor(.secondary)
                                }
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.green.opacity(0.1))
                            .cornerRadius(8)
                        } else if let errorMsg = validation.errorMessage {
                            HStack(spacing: 8) {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .foregroundColor(.orange)
                                    .font(.system(size: 14))
                                Text(errorMsg)
                                    .font(.system(size: 11))
                                    .foregroundColor(.orange)
                            }
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.orange.opacity(0.1))
                            .cornerRadius(8)
                        }
                    }

                    if let submissionError = submissionError {
                        Text(submissionError)
                            .font(.system(size: 11))
                            .foregroundColor(.red)
                    }
                }
                .padding(20)
            }

            Divider()

            // Footer Actions
            HStack {
                Button("Отмена") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)

                Spacer()

                Button("Добавить контакт") {
                    addContactAction()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!validation.isValid || isSubmitting)
                .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
        }
        .frame(width: 440, height: 380)
    }

    private func fillEchoBot() {
        self.name = "Echo Relay Node"
        self.keyInput = Self.echoBotKeyHex
    }

    private func addContactAction() {
        guard validation.isValid else { return }
        isSubmitting = true
        submissionError = nil

        Task {
            do {
                try await chatListVM.addContact(key: keyInput, name: name)
                isSubmitting = false
                dismiss()
            } catch {
                isSubmitting = false
                submissionError = error.localizedDescription
            }
        }
    }
}
