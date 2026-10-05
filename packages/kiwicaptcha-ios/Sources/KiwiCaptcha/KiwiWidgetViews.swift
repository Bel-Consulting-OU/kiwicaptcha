#if canImport(UIKit)
    import UIKit
    import SwiftUI

    /// The widget state, mirrored between the UIKit control and the
    /// SwiftUI view.
    @objc public enum KiwiWidgetState: Int {
        case idle
        case solving
        case verified
        case failed
        case expired
    }

    /// The UIKit widget: a status view that acquires, solves and expires
    /// a challenge on its own, and reports the token to the app. The
    /// token also lands in `token` for form serialization.
    public final class KiwiCaptchaUIView: UIControl {

        public var onVerify: ((String) -> Void)?
        public var onError: ((String) -> Void)?
        public var onExpire: (() -> Void)?

        public private(set) var token: String = ""
        public private(set) var state: KiwiWidgetState = .idle { didSet { render() } }

        private let client: KiwiClient
        private let scope: String
        private var task: Task<Void, Never>?
        private var expiryTask: Task<Void, Never>?

        private let statusLabel = UILabel()
        private let badgeLabel = UILabel()
        private let progress = UIProgressView(progressViewStyle: .default)
        private let retryButton = UIButton(type: .system)

        public init(client: KiwiClient, scope: String) {
            self.client = client
            self.scope = scope
            super.init(frame: CGRect(x: 0, y: 0, width: 320, height: 72))
            build()
            render()
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) { fatalError("init(client:scope:) is the only initializer") }

        private func build() {
            let stack = UIStackView(arrangedSubviews: [statusLabel, badgeLabel, progress, retryButton])
            stack.axis = .vertical
            stack.spacing = 4
            stack.translatesAutoresizingMaskIntoConstraints = false
            addSubview(stack)
            NSLayoutConstraint.activate([
                stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
                stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -16),
                stack.topAnchor.constraint(equalTo: topAnchor, constant: 12),
                stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -12),
            ])
            statusLabel.text = "Security Check"
            badgeLabel.font = .preferredFont(forTextStyle: .caption1)
            statusLabel.font = .preferredFont(forTextStyle: .body)
            retryButton.setTitle("Retry", for: .normal)
            retryButton.addTarget(self, action: #selector(start), for: .touchUpInside)
            retryButton.isHidden = true
            isAccessibilityElement = true
            accessibilityLabel = "Security Check"
            accessibilityTraits = [.staticText]
        }

        /// Acquire and solve a challenge. Safe to call again: the
        /// previous run is cancelled first.
        @objc public func start() {
            task?.cancel()
            expiryTask?.cancel()
            token = ""
            state = .solving
            let client = client
            let scope = scope
            task = Task { [weak self] in
                do {
                    let challenge = try await client.fetchChallenge(scope: scope)
                    guard !Task.isCancelled else { return }
                    let solution = try KiwiSolver.solve(challenge: challenge)
                    guard !Task.isCancelled else { return }
                    let token = KiwiToken.encode(challenge: challenge, solution: solution)
                    await MainActor.run { self?.verify(token, ttlSecs: challenge.ttlSecs ?? 0) }
                } catch is CancellationError {
                    return
                } catch {
                    await MainActor.run { self?.fail(String(describing: error)) }
                }
            }
        }

        private func verify(_ token: String, ttlSecs: UInt64) {
            self.token = token
            state = .verified
            onVerify?(token)
            accessibilityValue = "Verification complete"
            guard ttlSecs > 0 else { return }
            expiryTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(ttlSecs) * 1_000_000_000)
                guard !Task.isCancelled else { return }
                await MainActor.run { self?.expire() }
            }
        }

        private func fail(_ message: String) {
            token = ""
            state = .failed
            accessibilityValue = "Verification failed"
            onError?(message)
        }

        private func expire() {
            token = ""
            state = .expired
            onExpire?()
        }

        private func render() {
            switch state {
            case .idle: badgeLabel.text = "Idle"; progress.progress = 0
            case .solving: badgeLabel.text = "Working"; progress.progress = 0.5
            case .verified: badgeLabel.text = "Success"; progress.progress = 1
            case .failed: badgeLabel.text = "Failed"; progress.progress = 0
            case .expired: badgeLabel.text = "Expired"; progress.progress = 0
            }
            retryButton.isHidden = state != .failed && state != .expired
        }
    }

    /// The SwiftUI widget: the UIKit control, re-exported with callbacks
    /// and auto-start on appear.
    public struct KiwiCaptchaView: UIViewRepresentable {
        public var endpoint: URL
        public var scope: String
        public var sitekey: String?
        public var onVerify: (String) -> Void
        public var onError: (String) -> Void
        public var onExpire: () -> Void

        public init(
            endpoint: URL, scope: String, sitekey: String? = nil,
            onVerify: @escaping (String) -> Void,
            onError: @escaping (String) -> Void = { _ in },
            onExpire: @escaping () -> Void = {}
        ) {
            self.endpoint = endpoint
            self.scope = scope
            self.sitekey = sitekey
            self.onVerify = onVerify
            self.onError = onError
            self.onExpire = onExpire
        }

        public func makeUIView(context: Context) -> KiwiCaptchaUIView {
            let view = KiwiCaptchaUIView(
                client: KiwiClient(endpoint: endpoint, sitekey: sitekey),
                scope: scope)
            view.onVerify = onVerify
            view.onError = onError
            view.onExpire = onExpire
            view.start()
            return view
        }

        public func updateUIView(_ uiView: KiwiCaptchaUIView, context: Context) {}
    }
#endif
