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

        private var client: KiwiClient
        public private(set) var scope: String
        /// The configuration the live client was built from. SwiftUI's
        /// `updateUIView` compares these against the incoming values.
        public private(set) var endpoint: URL
        public private(set) var sitekey: String?
        /// The in-flight work. Internal so the test target (@testable)
        /// can assert a configuration change cancels the previous run.
        private(set) var task: Task<Void, Never>?
        private(set) var expiryTask: Task<Void, Never>?
        /// Number of full teardown/rebuild cycles (observability for the
        /// update path; also makes the no-op case assertable).
        private(set) var restartCount: Int = 0

        private let statusLabel = UILabel()
        private let badgeLabel = UILabel()
        private let progress = UIProgressView(progressViewStyle: .default)
        private let retryButton = UIButton(type: .system)

        public init(client: KiwiClient, scope: String) {
            self.client = client
            self.scope = scope
            self.endpoint = client.endpoint
            self.sitekey = client.sitekey
            super.init(frame: CGRect(x: 0, y: 0, width: 320, height: 72))
            build()
            render()
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) { fatalError("init(client:scope:) is the only initializer") }

        deinit {
            // A view leaving the hierarchy cancels both the solve and the
            // expiry timer: neither task may outlive the widget.
            task?.cancel()
            expiryTask?.cancel()
        }

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

        /// Cancel and release both in-flight tasks. Cancellation is
        /// cooperative; the solves check `Task.isCancelled` after each
        /// await, and the expiry task's sleep throws on cancellation.
        private func cancelTasks() {
            task?.cancel()
            task = nil
            expiryTask?.cancel()
            expiryTask = nil
        }

        /// Apply a new SwiftUI configuration. Callbacks are always
        /// refreshed (they are read at invocation, so a changed closure
        /// takes effect immediately). A changed endpoint, scope or
        /// sitekey invalidates the pending challenge, so the widget is
        /// torn down and restarted against the new connection; an
        /// unchanged configuration is a no-op (no timer churn, no second
        /// solve). Returns true when a restart happened.
        @discardableResult
        public func applyConfiguration(
            endpoint: URL, scope: String, sitekey: String?,
            onVerify: @escaping (String) -> Void,
            onError: @escaping (String) -> Void = { _ in },
            onExpire: @escaping () -> Void = {}
        ) -> Bool {
            self.onVerify = onVerify
            self.onError = onError
            self.onExpire = onExpire
            guard endpoint != self.endpoint || scope != self.scope || sitekey != self.sitekey
            else { return false }
            cancelTasks()
            self.endpoint = endpoint
            self.scope = scope
            self.sitekey = sitekey
            // Rebuild the client but keep the session: a host may have
            // injected a custom URLSession (tests do; apps may pin a
            // certificate policy). Nothing else from the old run is
            // carried over.
            self.client = KiwiClient(
                endpoint: endpoint, sitekey: sitekey, session: client.session)
            token = ""
            state = .idle
            accessibilityValue = nil
            restartCount += 1
            start()
            return true
        }

        /// Acquire and solve a challenge. Safe to call again: the
        /// previous run is cancelled first.
        @objc public func start() {
            cancelTasks()
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
                    guard !Task.isCancelled else { return }
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

        public func updateUIView(_ uiView: KiwiCaptchaUIView, context: Context) {
            // SwiftUI calls this after every parent update. The widget
            // refreshes its callbacks either way, and tears down/rebuilds
            // the run only when endpoint, scope or sitekey changed; the
            // previous task and expiry timer are cancelled first, so no
            // observer or task is left behind.
            uiView.applyConfiguration(
                endpoint: endpoint,
                scope: scope,
                sitekey: sitekey,
                onVerify: onVerify,
                onError: onError,
                onExpire: onExpire)
        }
    }
#endif
