import UIKit

/// Create an instance with your configuration, hold a reference to it, and forward incoming
/// deep links to ``handle(_:)``.
@MainActor
public final class KrdpassAuth {

    /// Shared singleton instance, set by ``initialize(_:urlSession:)``.
    public private(set) static var shared: KrdpassAuth?

    /// Configure the shared singleton instance.
    ///
    /// `urlSession` is used for every request the SDK makes; supply one to pin certificates or
    /// proxy. The default is ephemeral, not `URLSession.shared`: token and userinfo responses
    /// must not ride the app's shared on-disk `URLCache` and cookie jar.
    @discardableResult
    public static func initialize(
        _ config: KrdpassConfig,
        urlSession: URLSession = URLSession(configuration: .ephemeral)
    ) -> KrdpassAuth {
        let instance = KrdpassAuth(
            config: config, urlOpener: DefaultUrlOpener(), urlSession: urlSession)
        shared = instance
        return instance
    }

    public var logger: KrdpassLogger?

    let config: KrdpassConfig

    private var completionHandler: ((AuthResult) -> Void)?

    public private(set) var isAuthenticating: Bool = false

    private var currentState: String?

    /// RS256/JWKS token verification: signature, iss/aud/exp, JWKS cache and rotation.
    lazy var jwtVerifier = JwtVerifier(
        jwksEndpoint: config.environment.jwksEndpoint,
        urlSession: urlSession,
        log: { [weak self] level, message in
            // verify() runs off the main actor, so hop back for the @MainActor log.
            Task { @MainActor in self?.log(level, message) }
        }
    )

    private var timeoutTask: Task<Void, Never>?
    // Held so teardownAuth can cancel it: PAR retries with backoff for up to ~93s, and a flow
    // the caller already cancelled must stop talking to the authorization server.
    private var flowTask: Task<Void, Never>?

    /// Detects the user returning to the app without finishing in KRDPASS and cancels the
    /// in-flight flow. See ``ForegroundReturnWatcher``.
    private lazy var foregroundWatcher = ForegroundReturnWatcher(
        log: { [weak self] level, message in self?.log(level, message) },
        isStillPending: { [weak self] in self?.isAuthenticating ?? false },
        onAbandoned: { [weak self] in self?.complete(with: .cancelled) }
    )

    public convenience init(
        config: KrdpassConfig,
        urlSession: URLSession = URLSession(configuration: .ephemeral)
    ) {
        self.init(config: config, urlOpener: DefaultUrlOpener(), urlSession: urlSession)
    }

    init(
        config: KrdpassConfig,
        urlOpener: UrlOpener = DefaultUrlOpener(),
        urlSession: URLSession = URLSession(configuration: .ephemeral)
    ) {
        self.config = config
        self.urlOpener = urlOpener
        self.urlSession = urlSession
        self.casClient = CasClient(
            clientId: config.clientId, environment: config.environment, urlSession: urlSession)
    }
    private let urlOpener: UrlOpener
    /// `Sendable`, so the nonisolated token calls read it without hopping to the main actor.
    let casClient: CasClient
    let urlSession: URLSession

    func log(_ levelString: String, _ message: String) {
        guard let logger = logger else { return }
        logger.log(level: levelString, message: message)
    }

    private func validateInteractiveConfig() throws {
        let clientId = config.clientId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clientId.isEmpty else {
            throw KrdpassError.configurationError("clientId cannot be empty")
        }

        let redirectUri = config.redirectUri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !redirectUri.isEmpty else {
            throw KrdpassError.configurationError("redirectUri cannot be empty")
        }

        guard let url = URL(string: redirectUri) else {
            throw KrdpassError.configurationError("redirectUri must be a valid URL")
        }

        guard url.scheme == "https" else {
            throw KrdpassError.configurationError("redirectUri must use HTTPS")
        }

        guard let host = url.host, !host.isEmpty else {
            throw KrdpassError.configurationError("redirectUri must have a valid host")
        }

        guard config.isValidRedirectUri(url) else {
            throw KrdpassError.configurationError(
                "redirectUri must not contain user info, a fragment, malformed encoding, "
                    + "or OAuth response parameters")
        }
    }

    func buildAuthorizationUrl(requestUri: String, state: String) throws -> String {
        guard !requestUri.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw KrdpassError.configurationError("requestUri cannot be empty")
        }

        let clientId = config.clientId
        let environment = config.environment

        guard var components = URLComponents(string: environment.authUrl) else {
            throw KrdpassError.configurationError("Invalid environment authUrl")
        }
        // `redirect_uri` is redundant under RFC 9126, which binds it in the PAR body, but the
        // provider reads it from here to send the user back before it resolves the request_uri;
        // dropping it strands the flow with no callback at all on every already-installed
        // KRDPASS build. `state` rides along because the provider echoes it on redirects it
        // generates before resolving the request_uri.
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "request_uri", value: requestUri),
            URLQueryItem(name: "redirect_uri", value: config.redirectUri),
            URLQueryItem(name: "state", value: state),
        ]

        guard let url = components.url else {
            throw KrdpassError.configurationError("Failed to build authorization URL")
        }
        return url.absoluteString
    }

    public var currentConfig: KrdpassConfig {
        return config
    }

    /// Launch KRDPASS for authentication.
    ///
    /// `requestUri` and `state` come from your backend's PAR call; `state` is echoed back for
    /// CSRF checking.
    public func authenticate(
        requestUri: String,
        state: String,
        timeout: TimeInterval = 300.0,
        completion: @escaping (AuthResult) -> Void
    ) {
        do {
            try validateInteractiveConfig()
        } catch {
            completion(.error(AuthError.invalidRequest(error.localizedDescription)))
            return
        }

        guard !requestUri.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            completion(
                .error(
                    AuthError.platformError("requestUri cannot be empty")))
            return
        }
        guard timeout > 0 else {
            completion(
                .error(
                    AuthError.platformError("timeout must be positive")))
            return
        }

        // state is mandatory for CSRF / response-injection protection (RFC 6749 Section 10.12).
        guard !state.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            completion(.error(.invalidRequest(KrdpassMessages.stateRequired)))
            return
        }

        guard !isAuthenticating else {
            log("WARN", "authenticate called while already authenticating")
            completion(.busy)
            return
        }

        log("INFO", "Starting authentication flow")

        let authUrlString: String
        do {
            authUrlString = try buildAuthorizationUrl(requestUri: requestUri, state: state)
        } catch {
            completion(
                .error(
                    AuthError.launchFailed(
                        "Failed to build authorization URL: \(error.localizedDescription)")))
            return
        }
        // Never log the full auth URL: it carries the request parameters.
        log("DEBUG", "Launching KRDPASS URL")
        guard let authUrl = URL(string: authUrlString) else {
            completion(.error(AuthError.launchFailed("Failed to build authorization URL")))
            return
        }

        isAuthenticating = true
        completionHandler = completion
        currentState = state

        // An open callback that never lands would otherwise leave the flow pending forever.
        scheduleTimeout(timeout, state: state)

        // App-to-app: universalLinksOnly:true opens ONLY the genuine KRDPASS app (it has verified
        // ownership of the authorization domain) and fails closed instead of degrading to Safari.
        let installUrl = config.environment.installUrl
        urlOpener.open(authUrl, options: [.universalLinksOnly: true]) { [weak self] success in
            guard let self = self else { return }
            // This callback lands after an app-switch round trip; only act while it is still
            // this flow.
            guard self.isAuthenticating, self.currentState == state else { return }
            if !success {
                self.complete(with: .error(.providerNotInstalled(installUrl: installUrl)))
            } else {
                self.foregroundWatcher.start()
            }
        }
    }

    public func authenticate(
        requestUri: String, state: String, timeout: TimeInterval = 300.0
    ) async -> AuthResult {
        await withCheckedContinuation { continuation in
            authenticate(requestUri: requestUri, state: state, timeout: timeout) { result in
                continuation.resume(returning: result)
            }
        }
    }

    /// Check if the SDK can handle the given URL, i.e. it is a KRDPASS redirect for an
    /// in-flight flow.
    public func canHandle(_ url: URL) -> Bool {
        guard isAuthenticating else { return false }
        return config.isValidRedirectUri(url)
    }

    /// Handle a deep link URL received from the system.
    ///
    /// - Returns: True if the URL was handled, false if it should be passed to other handlers.
    @discardableResult
    public func handle(_ url: URL) -> Bool {
        guard canHandle(url) else { return false }
        foregroundWatcher.markDeepLinkForwarded()

        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return false
        }

        let queryItems = components.queryItems ?? []
        // The callback URL is third-party-controllable (any app/page can fire the Universal
        // Link), so a duplicate query key must NOT trap. Last value wins; the state check below
        // still rejects a forged/duplicated state.
        let params = Dictionary(
            queryItems.compactMap { item -> (String, String)? in
                guard let value = item.value else { return nil }
                return (item.name, value)
            },
            uniquingKeysWith: { _, last in last })

        complete(
            with: Self.decideAuthResult(
                code: params["code"],
                returnedState: params["state"],
                error: params["error"],
                errorDescription: params["error_description"],
                returnedIss: params["iss"],
                expectedState: currentState,
                expectedIssuer: config.environment.authServerUrl))
        return true
    }

    /// Cancel any in-flight authentication (authenticate/signIn) flow.
    ///
    /// - Parameter timeout: when true, completes as `.timeout` instead of `.cancelled`.
    public func cancelPendingAuthentication(timeout: Bool = false) {
        if isAuthenticating {
            complete(with: timeout ? .timeout : .cancelled)
        }
    }

    /// Generate a PKCE code verifier and challenge pair.
    ///
    /// - Throws: ``KrdpassError/pkceGenerationFailed`` when the device's secure random source
    ///   fails.
    public nonisolated func generatePkcePair() throws -> PkcePair {
        do {
            return try PkceGenerator.generate()
        } catch {
            throw KrdpassError.pkceGenerationFailed
        }
    }

    /// Generate a random `state` value for the server-mediated flow.
    ///
    /// - Throws: ``KrdpassError/pkceGenerationFailed`` when the device's secure random source
    ///   fails.
    public nonisolated func generateState() throws -> String {
        do {
            let stateBytes = try PkceGenerator.generateRandomBytes(count: 32)
            return PkceGenerator.base64UrlEncodeNoPadding(stateBytes)
        } catch {
            throw KrdpassError.pkceGenerationFailed
        }
    }

    /// Perform client-only authentication with KRDPASS, without requiring a backend server:
    /// PKCE, PAR, app launch, and code-for-tokens exchange are all handled internally.
    public func signIn(
        scopes: [String] = [KrdpassScopes.openid, KrdpassScopes.profile],
        timeout: TimeInterval = 300,
        completion: @escaping (Result<KrdpassTokenResult, KrdpassError>) -> Void
    ) {
        do {
            try validateInteractiveConfig()
        } catch let error as KrdpassError {
            completion(.failure(error))
            return
        } catch {
            completion(.failure(.configurationError(error.localizedDescription)))
            return
        }

        guard !scopes.isEmpty else {
            completion(.failure(.configurationError("scopes cannot be empty")))
            return
        }
        guard timeout > 0 else {
            completion(.failure(.configurationError("timeout must be positive")))
            return
        }

        guard !isAuthenticating else {
            completion(.failure(.busy))
            return
        }

        // Generated before the flow is claimed: a secure-random failure must not leave
        // `isAuthenticating` stuck true.
        let pkcePair: PkcePair
        let state: String
        let nonce: String
        do {
            pkcePair = try generatePkcePair()
            state = try generateState()
            // OIDC nonce: bound into PAR, verified against the returned id_token to detect replay.
            nonce = try generateState()
        } catch {
            completion(.failure(KrdpassAuth.asKrdpassError(error)))
            return
        }

        isAuthenticating = true
        currentState = state

        // PAR retries and backoff can wedge for ~93s. `deadline` is the real budget; the launch
        // callback re-arms what is left.
        let deadline = Date().addingTimeInterval(timeout)
        scheduleTimeout(timeout, state: state)

        // A teardown during the PAR await needs somewhere to land or the caller hears
        // `.userCancelled` for a timeout.
        completionHandler = { [weak self] authResult in
            guard let self = self else { return }

            Task {
                do {
                    switch authResult {
                    case .success(let response):
                        let tokens = try await self.casClient.exchangeCodeForTokens(
                            code: response.code,
                            codeVerifier: pkcePair.codeVerifier,
                            redirectUri: self.config.redirectUri
                        )
                        try await self.validateIdToken(tokens.idToken, expectedNonce: nonce)
                        completion(.success(tokens))

                    case .cancelled:
                        completion(.failure(.userCancelled))

                    case .timeout:
                        completion(.failure(.timeout))

                    case .busy:
                        completion(.failure(.busy))

                    case .error(let error):
                        completion(
                            .failure(.authenticationFailed(error.message, code: error.error)))
                    }
                } catch {
                    completion(.failure(KrdpassAuth.asKrdpassError(error)))
                }
            }
        }

        flowTask = Task {
            do {
                let parResponse = try await self.casClient.pushAuthorizationRequest(
                    codeChallenge: pkcePair.codeChallenge,
                    redirectUri: config.redirectUri,
                    scopes: scopes,
                    state: state,
                    nonce: nonce
                )

                // A teardown during the PAR await already reported through the installed handler;
                // reporting again would double-resume the async variant's continuation.
                guard isAuthenticating, currentState == state else { return }

                let authUrlString = try buildAuthorizationUrl(
                    requestUri: parResponse.requestUri, state: state)
                guard let authUrl = URL(string: authUrlString) else {
                    throw KrdpassError.configurationError("Failed to build authorization URL")
                }

                urlOpener.open(authUrl, options: [.universalLinksOnly: true]) {
                    [weak self] success in
                    guard let self = self else { return }
                    guard self.isAuthenticating, self.currentState == state else { return }
                    if !success {
                        self.teardownAuth()
                        completion(
                            .failure(
                                .providerNotInstalled(installUrl: config.environment.installUrl)))
                    } else {
                        // Don't wait past the request_uri's own expiry, nor past what the PAR
                        // phase left of the caller's budget.
                        let effectiveTimeout = min(
                            deadline.timeIntervalSinceNow, TimeInterval(parResponse.expiresIn))
                        self.scheduleTimeout(max(effectiveTimeout, 0), state: state)
                        self.foregroundWatcher.start()
                    }
                }

            } catch {
                guard isAuthenticating, currentState == state else { return }
                // teardownAuth() clears the handler installed above, so the report below is the
                // only one the caller gets. CasException maps to NetworkError in both signIn
                // phases.
                teardownAuth()
                completion(.failure(KrdpassAuth.asKrdpassError(error)))
            }
        }
    }

    public func signIn(
        scopes: [String] = [KrdpassScopes.openid, KrdpassScopes.profile],
        timeout: TimeInterval = 300
    ) async throws -> KrdpassTokenResult {
        try await withCheckedThrowingContinuation { continuation in
            signIn(scopes: scopes, timeout: timeout) { result in
                switch result {
                case .success(let tokens):
                    continuation.resume(returning: tokens)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Schedule the timeout for the flow identified by `state`. The token is re-checked after
    /// the sleep, so a stale timeout cannot tear down whichever flow is running when it lands.
    private func scheduleTimeout(_ timeout: TimeInterval, state: String) {
        cancelTimeout()

        let nanoseconds = UInt64(exactly: (max(timeout, 0) * 1_000_000_000).rounded()) ?? .max
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: nanoseconds)
            guard !Task.isCancelled, let self = self else { return }
            guard self.isAuthenticating, self.currentState == state else { return }
            self.complete(with: .timeout)
        }
    }

    private func cancelTimeout() {
        timeoutTask?.cancel()
        timeoutTask = nil
    }

    /// The single canonical teardown of the in-flight state. Every early-failure path must go
    /// through this: a site that forgets `completionHandler` leaves a dangling handler that a
    /// later flow's complete() would re-fire, double-resuming the async variants' continuations.
    @discardableResult
    private func teardownAuth() -> ((AuthResult) -> Void)? {
        cancelTimeout()
        foregroundWatcher.stop()
        // Cancelling from inside the task itself is a no-op for the code after the await (its
        // post-PAR guards already returned), so this is safe on every teardown path.
        flowTask?.cancel()
        flowTask = nil
        let handler = completionHandler
        completionHandler = nil
        currentState = nil
        isAuthenticating = false
        return handler
    }

    private func complete(with result: AuthResult) {
        cancelTimeout()

        switch result {
        case .success:
            log("INFO", "Authentication completed successfully")
        case .cancelled:
            log("INFO", "Authentication cancelled by user")
        case .timeout:
            log("WARN", "Authentication timed out")
        case .busy:
            log("WARN", "Authentication failed: busy")
        case .error(let error):
            log("ERROR", "Authentication failed: \(error.message)")
        }

        teardownAuth()?(result)
    }
}
