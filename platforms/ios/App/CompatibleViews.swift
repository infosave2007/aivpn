import SwiftUI
import UIKit

/// Keeps the single-column navigation used by the app on iOS 15 as well.
struct CompatibleNavigationView<Content: View>: View {
    private let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    @ViewBuilder var body: some View {
        if #available(iOS 16, *) {
            NavigationStack { content }
        } else {
            NavigationView { content }
                .navigationViewStyle(.stack)
        }
    }
}

struct CompatibleValueRow: View {
    private let title: String
    private let value: String

    init(_ title: String, value: String) {
        self.title = title
        self.value = value
    }

    var body: some View {
        HStack {
            Text(title)
            Spacer()
            Text(value)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
        }
        .accessibilityElement(children: .combine)
    }
}

/// iOS 15's TextEditor preserves multiline keys and certificates when pasted.
struct CompatibleMultilineTextField: View {
    private let title: String
    @Binding private var text: String
    private let lines: ClosedRange<Int>

    init(_ title: String, text: Binding<String>, lines: ClosedRange<Int>) {
        self.title = title
        self._text = text
        self.lines = lines
    }

    @ViewBuilder var body: some View {
        if #available(iOS 16, *) {
            TextField(title, text: $text, axis: .vertical)
                .lineLimit(lines)
        } else {
            ZStack(alignment: .topLeading) {
                TextEditor(text: $text)
                    .frame(height: CGFloat(min(lines.upperBound, max(lines.lowerBound, 3))) * 22 + 16)
                    .accessibilityLabel(Text(title))
                if text.isEmpty {
                    Text(title)
                        .foregroundColor(Color(UIColor.placeholderText))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 8)
                        .allowsHitTesting(false)
                        .accessibilityHidden(true)
                }
            }
        }
    }
}

struct CompatibleShareLink<Label: View>: View {
    let item: String
    private let label: Label
    @State private var isPresented = false

    init(item: String, @ViewBuilder label: () -> Label) {
        self.item = item
        self.label = label()
    }

    @ViewBuilder var body: some View {
        if #available(iOS 16, *) {
            ShareLink(item: item) { label }
        } else {
            Button { isPresented = true } label: { label }
                .sheet(isPresented: $isPresented) {
                    ActivitySheet(item: item)
                }
        }
    }
}

private struct ActivitySheet: UIViewControllerRepresentable {
    let item: String

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [item], applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

extension View {
    @ViewBuilder func compatibleNavigationBarBackground(_ color: Color) -> some View {
        if #available(iOS 16, *) {
            self.toolbarBackground(color, for: .navigationBar)
                .toolbarBackground(.visible, for: .navigationBar)
        } else {
            self
        }
    }
}
