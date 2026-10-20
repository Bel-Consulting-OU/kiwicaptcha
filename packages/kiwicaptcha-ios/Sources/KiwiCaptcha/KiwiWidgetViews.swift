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

    /// The monotonic generation counter behind cooperative
    /// cancellation. Only the newest generation may emit: a restart,
    /// a teardown or the expiry deadline advances the counter, every
    /// earlier generation's solve probe fires at the next checkpoint,
    /// and stale results are discarded. Probes read it from solver
    /// threads while the widget mutates it on the main thread, so it
    /// is lock-guarded, not a bare Int.
    private final class KiwiGenerationCounter: @unchecked Sendable {
        private let lock = NSLock()
        private var current = 0

        /// Invalidate every earlier generation and return the new one.
        func advance() -> Int {
            lock.lock(); defer { lock.unlock() }
            current += 1
            return current
        }

        func isCurrent(_ generation: Int) -> Bool {
            lock.lock(); defer { lock.unlock() }
            return generation == current
        }
    }

    /// The UIKit widget: a status view that acquires, solves and
    /// expires a challenge on its own, and reports the token to the
    /// app. The token also lands in `token` for form serialization.
    ///
    /// The run follows the Interactive-Client Lifecycle v1 contract:
    /// the clocks start the moment the challenge JSON parses, the
    /// expiry timer races the solve, a finished solve waits out the
    /// issued minimum duration before delivery, and only the newest
    /// generation emits.
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
        /// The generation the in-flight work belongs to; only the
        /// newest may emit.
        private let generations = KiwiGenerationCounter()
        /// Number of full teardown/rebuild cycles (observability for the
        /// update path; also makes the no-op case assertable).
        private(set) var restartCount: Int = 0

        // The outlets are internal so the test target (@testable) can
        // assert the accessibility wiring.
        let statusLabel = UILabel()
        let badgeLabel = UILabel()
        let progress = UIProgressView(progressViewStyle: .default)
        let retryButton = UIButton(type: .system)
        /// The last state accessibility announced, so a render that
        /// does not change the state stays silent.
        private var announcedState: KiwiWidgetState?

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
            // A view leaving the hierarchy invalidates the generation
            // (an in-flight solve stops at its next checkpoint) and
            // cancels both tasks: neither may outlive the widget.
            generations.advance()
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

            // Accessibility: the container is not one collapsed
            // element — the Retry button stays a real, reachable
            // button. The status label is the live region (its value
            // tracks the state word) and the progress bar reports its
            // own percentage; state transitions are announced below.
            statusLabel.isAccessibilityElement = true
            statusLabel.accessibilityLabel = "Security check status"
            statusLabel.accessibilityTraits = [.updatesFrequently]
            badgeLabel.isAccessibilityElement = false
            progress.isAccessibilityElement = true
            progress.accessibilityLabel = "Security check progress"
            retryButton.accessibilityHint = "Runs the security check again"
        }

        /// Cancel and release both in-flight tasks. Advancing the
        /// generation invalidates the run: the solve's probe fires at
        /// its next bounded-latency checkpoint (sha256 every 2048
        /// candidates, argon2id between derivations, rsw every 256
        /// squarings) and stops the CPU work; the sleeps throw on
        /// cancellation.
        private func cancelTasks() {
            generations.advance()
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
            restartCount += 1
            start()
            return true
        }

        /// Acquire and solve a challenge. Safe to call again: the
        /// previous run's generation is invalidated first, so its
        /// solve stops at the next checkpoint and its results are
        /// discarded even if a checkpoint was never reached.
        @objc public func start() {
            cancelTasks()
            token = ""
            state = .solving
            let client = client
            let scope = scope
            let generation = generations.advance()
            // The solver's cancellation probe: it fires the moment
            // this generation stops being the newest (a restart, a
            // teardown, the expiry deadline) or the view is gone.
            let probe: @Sendable () -> Bool = { [weak self] in
                guard let self else { return true }
                return !self.generations.isCurrent(generation)
            }
            task = Task { [weak self] in
                do {
                    let challenge = try await client.fetchChallenge(scope: scope)
                    guard !Task.isCancelled, !probe() else { return }

                    // Lifecycle v1: `receivedAtMs` is captured
                    // immediately after the challenge JSON parses, and
                    // every clock — expiry and min-submit alike — runs
                    // from there, never from after the solve.
                    let receivedAtMs = Self.nowMs()
                    let ttlSecs = Int64(challenge.ttlSecs ?? 0)
                    let minDurationMs = Int64(challenge.minDurationMs ?? 0)
                    let expiresAtMs = KiwiLifecycle.expiresAt(
                        receivedAtMs: receivedAtMs, ttlSecs: ttlSecs)

                    // Arm the expiry timer at parse time. It now
                    // races the solve, which is the contract's point:
                    // a solve that outlives the deadline is
                    // invalidated at its next checkpoint and can
                    // never deliver.
                    await MainActor.run {
                        self?.armExpiry(generation, expiresAtMs: expiresAtMs)
                    }
                    guard !Task.isCancelled, !probe() else { return }

                    // The proof of work is pure CPU: run it detached
                    // at user-initiated priority so the main thread
                    // never freezes behind the SHA search, the
                    // argon2id derivations or the rsw squarings. Only
                    // UI state updates marshal back to the main
                    // actor.
                    let solution = try await Task.detached(priority: .userInitiated) {
                        try KiwiSolver.solve(challenge: challenge, isCancelled: probe)
                    }.value
                    let solveFinishedAtMs = Self.nowMs()

                    // Delivery gating: min-submit defers the finished
                    // token (cancellably) to the floor; anything the
                    // pure helper calls expired is never delivered.
                    var decision = KiwiLifecycle.deliveryDecision(
                        receivedAtMs: receivedAtMs, ttlSecs: ttlSecs,
                        minDurationMs: minDurationMs,
                        solveFinishedAtMs: solveFinishedAtMs,
                        nowMs: solveFinishedAtMs)
                    if decision.reason == "defer" {
                        let holdMs = decision.deliverAtMs - Self.nowMs()
                        if holdMs > 0 {
                            try await Task.sleep(nanoseconds: UInt64(holdMs) * 1_000_000)
                        }
                        guard !Task.isCancelled, !probe() else { return }
                        decision = KiwiLifecycle.deliveryDecision(
                            receivedAtMs: receivedAtMs, ttlSecs: ttlSecs,
                            minDurationMs: minDurationMs,
                            solveFinishedAtMs: solveFinishedAtMs,
                            nowMs: Self.nowMs())
                    }
                    guard decision.reason == "deliver" else { return }

                    // The last gate before onVerify: never deliver at
                    // or after the deadline.
                    guard expiresAtMs == Int64.max || Self.nowMs() < expiresAtMs else { return }
                    let token = KiwiToken.encode(challenge: challenge, solution: solution)
                    await MainActor.run {
                        // Only the newest generation emits; a
                        // superseded result is discarded here.
                        guard let self, self.generations.isCurrent(generation) else { return }
                        self.token = token
                        self.state = .verified
                        self.onVerify?(token)
                    }
                } catch is CancellationError {
                    return
                } catch let error as KiwiSolveError where error == .cancelled {
                    // The probe fired mid-solve; the generation is
                    // already gone, so there is nothing to report.
                    return
                } catch {
                    guard !Task.isCancelled, !probe() else { return }
                    await MainActor.run { self?.fail(String(describing: error)) }
                }
            }
        }

        /// Arm the deadline for a generation, measured from parse
        /// time (minus the fixed 1 s safety margin, already folded
        /// into `expiresAtMs`). Called right after the challenge
        /// parses, so the timer races the solve.
        private func armExpiry(_ generation: Int, expiresAtMs: Int64) {
            guard expiresAtMs != Int64.max, generations.isCurrent(generation) else { return }
            expiryTask = Task { [weak self] in
                // Cancellable sleep to the deadline. Main-actor
                // context: this Task was created inside MainActor.run.
                let delayMs = expiresAtMs - Self.nowMs()
                if delayMs > 0 {
                    try? await Task.sleep(nanoseconds: UInt64(delayMs) * 1_000_000)
                }
                guard let self, !Task.isCancelled,
                      self.generations.isCurrent(generation) else { return }
                self.expireGeneration(generation)
            }
        }

        /// The deadline fired for a live generation: invalidate it (an
        /// in-flight solve stops at its next checkpoint and a late
        /// result is discarded), drop both tasks and show the expired
        /// state.
        private func expireGeneration(_ generation: Int) {
            guard generations.isCurrent(generation) else { return }
            generations.advance()
            task?.cancel()
            task = nil
            expiryTask?.cancel()
            expiryTask = nil
            token = ""
            state = .expired
            onExpire?()
        }

        private func fail(_ message: String) {
            token = ""
            state = .failed
            onError?(message)
        }

        /// Wall-clock milliseconds. Lifecycle v1 uses the wall clock:
        /// the deadline is anchored to the server's issue time.
        static func nowMs() -> Int64 {
            Int64(Date().timeIntervalSince1970 * 1000)
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
            progress.accessibilityValue = "\(Int((progress.progress * 100).rounded())) percent"
            // The status label is the live region: its value tracks
            // the state word, and attention-worthy transitions are
            // announced through UIAccessibility.
            statusLabel.accessibilityValue = badgeLabel.text
            guard state != announcedState else { return }
            announcedState = state
            switch state {
            case .verified:
                UIAccessibility.post(notification: .announcement, argument: "Security check complete")
            case .failed:
                UIAccessibility.post(notification: .announcement, argument: "Security check failed. Retry available")
            case .expired:
                UIAccessibility.post(notification: .announcement, argument: "Security check expired. Retry available")
            case .idle, .solving:
                break
            }
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
            // previous generation is invalidated and both tasks are
            // cancelled first, so no observer or task is left behind.
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
