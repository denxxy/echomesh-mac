import SwiftUI

public struct ChatDetailView: View {
    @Bindable var chatVM: ChatViewModel
    var appState: AppState

    public init(chatVM: ChatViewModel, appState: AppState) {
        self.chatVM = chatVM
        self.appState = appState
    }

    public var body: some View {
        ChatView(chatVM: chatVM, appState: appState)
    }
}
