import SwiftUI

/// Explains what the app sends and stores. Shown once before the app asks for
/// the VPN configuration or for notifications, and later from the main
/// screen footer.
struct DataUseNoticeView: View {
    /// On first launch the only way forward is the Continue button.
    let isFirstLaunch: Bool
    let onClose: () -> Void

    @EnvironmentObject private var loc: LocalizationManager
    @Environment(\.openURL) private var openURL

    private struct Point: Identifiable {
        let id: String
        let symbol: String
    }

    private let points = [
        Point(id: "server", symbol: "server.rack"),
        Point(id: "collect", symbol: "hand.raised.fill"),
        Point(id: "operator", symbol: "eye.fill"),
        Point(id: "storage", symbol: "lock.fill"),
        Point(id: "optional", symbol: "slider.horizontal.3"),
    ]

    private var policyURL: URL? {
        let file = loc.language == "ru" ? "PRIVACY_RU.md" : "PRIVACY.md"
        return URL(string: "https://github.com/infosave2007/aivpn/blob/master/\(file)")
    }

    var body: some View {
        CompatibleNavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text(loc.t("notice_heading"))
                        .font(.title2)
                        .fontWeight(.bold)
                        .fixedSize(horizontal: false, vertical: true)

                    ForEach(points) { point in
                        HStack(alignment: .top, spacing: 14) {
                            Image(systemName: point.symbol)
                                .font(.title3)
                                .foregroundColor(.accentColor)
                                .frame(width: 30)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 4) {
                                Text(loc.t("notice_\(point.id)_title"))
                                    .font(.headline)
                                Text(loc.t("notice_\(point.id)_body"))
                                    .font(.subheadline)
                                    .foregroundColor(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }

                    Button {
                        if let url = policyURL { openURL(url) }
                    } label: {
                        Label(loc.t("notice_policy_link"), systemImage: "doc.text")
                            .font(.subheadline)
                    }
                    .padding(.leading, 44)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)
                .frame(maxWidth: 560, alignment: .leading)
                .frame(maxWidth: .infinity)
            }
            .safeAreaInset(edge: .bottom, spacing: 0) {
                if isFirstLaunch {
                    Button(action: onClose) {
                        Text(loc.t("notice_continue"))
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .frame(maxWidth: 560)
                    .padding(.horizontal, 20)
                    .padding(.top, 12)
                    .padding(.bottom, 8)
                    .frame(maxWidth: .infinity)
                    .background(.ultraThinMaterial, ignoresSafeAreaEdges: .bottom)
                }
            }
            .navigationTitle(loc.t("notice_title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    if isFirstLaunch {
                        Button { loc.toggleLanguage() } label: {
                            Text(loc.language == "en" ? "RU" : "EN")
                                .font(.caption)
                                .padding(4)
                                .background(Color(.secondarySystemBackground))
                                .cornerRadius(6)
                        }
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if !isFirstLaunch {
                        Button(loc.t("done"), action: onClose)
                    }
                }
            }
        }
        .interactiveDismissDisabled(isFirstLaunch)
    }
}
