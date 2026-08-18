// Compile-only guard for the code samples in README.md. Nothing here is executed; the
// point is that the build fails if a README example stops matching the public API.
// Keep each block a verbatim copy of the README, minus the surrounding prose.

import KrdpassAuth
import SwiftUI
import UIKit
import XCTest

private let config = KrdpassConfig(
    clientId: "your-client-id",
    redirectUri: "https://auth.your-app.example.com/callback",  // HTTPS Universal Link
    environment: .production
)

// The SwiftUI platform-setup block. Not @main here (the test bundle has its own entry
// point), otherwise verbatim.
private struct MyApp: App {
    private let auth = KrdpassAuth.initialize(config)  // config as in Quickstart

    var body: some Scene {
        WindowGroup {
            ContentView().withKrdpassDeepLinkHandling(auth)
        }
    }
}

private struct ContentView: View {
    var body: some View { EmptyView() }
}

// The UIKit platform-setup block.
private final class SampleAppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        continue userActivity: NSUserActivity,
        restorationHandler: @escaping ([UIUserActivityRestoring]?) -> Void
    ) -> Bool {
        guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
            let url = userActivity.webpageURL,
            let auth = KrdpassAuth.shared, auth.canHandle(url)
        else { return false }
        return auth.handle(url)
    }
}

@MainActor
private func readingCitizenIdentity(auth: KrdpassAuth, tokens: KrdpassTokenResult) async throws {
    let info = try await auth.getUserInfo(accessToken: tokens.accessToken)
    let upn = info.upn  // the citizen's UPN
    let fullName = info.citizenFullName  // name parts joined, nil when none are present
    let birthdate = info.birthdate
    _ = (upn, fullName, birthdate, info.raw)

    let scoped = try await auth.signIn(
        scopes: [KrdpassScopes.openid, KrdpassScopes.profile, KrdpassScopes.citizenIdentity])
    _ = scoped
}

@MainActor
private func quickstartClientOnlyAsync(auth: KrdpassAuth) async throws {
    let tokens = try await auth.signIn(scopes: ["openid", "profile"])
    _ = tokens.accessToken
}

@MainActor
private func quickstartClientOnlyCallback(auth: KrdpassAuth) {
    auth.signIn(scopes: ["openid", "profile"]) { result in
        switch result {
        case .success(let tokens):
            _ = tokens.accessToken
        case .failure(let error):
            // error.code, error.errorDescription, error.installUrl
            _ = (error.code, error.errorDescription, error.installUrl)
        }
    }
}

@MainActor
private func quickstartInitializeReturnsInstance() {
    let auth = KrdpassAuth.initialize(config)
    _ = auth
}

private final class SampleLogger: KrdpassLogger {
    func log(level: String, message: String) {}
}

@MainActor
private func quickstartLogging(auth: KrdpassAuth) {
    auth.logger = SampleLogger()
}

@MainActor
private func quickstartPkceAndState(auth: KrdpassAuth) throws {
    let pkce = try auth.generatePkcePair()
    let state = try auth.generateState()
    _ = (pkce.codeChallenge, pkce.codeVerifier, state)
}

@MainActor
private func quickstartServerMediated(auth: KrdpassAuth, requestUri: String, state: String) {
    auth.authenticate(requestUri: requestUri, state: state) { result in
        switch result {
        case .success(let response):
            _ = (response.code, response.state)  // send both to your backend
        case .cancelled:
            break  // user came back without finishing; usually no UI needed
        case .timeout:
            break  // offer retry
        case .busy:
            break  // ignore or queue
        case .error(let error):
            // A cancellation KRDPASS reports on the redirect lands here with
            // error.error == "cancelled", not in the .cancelled case above.
            _ = (error.error, error.errorDescription, error.installUrl)
        }
    }
}

@MainActor
private func refreshingKeepsExistingRefreshToken(
    auth: KrdpassAuth, storedRefreshToken: inout String
) async throws {
    let refreshed = try await auth.refreshTokens(refreshToken: storedRefreshToken)
    storedRefreshToken = refreshed.refreshToken ?? storedRefreshToken
}

final class ReadmeSamplesCompileTests: XCTestCase {
    func testReadmeSamplesCompile() {
        XCTAssertFalse(config.clientId.isEmpty)
    }
}
