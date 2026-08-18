# KRDPASS Auth SDK (iOS)

Sign in with KRDPASS for native iOS apps. The SDK hands off to the installed KRDPASS
identity app over a Universal Link and receives the result back at your Universal Link
redirect URI. It is not a browser or WebView flow.

Full integration guide, onboarding, error codes and security requirements:
**[KRDPASS documentation](https://docs.digital.gov.krd/software-development/04-interoperability/11-krdpass-sign-in-with-krdpass.html)**

## Requirements

- iOS 15.0, Swift 6.0 (Xcode 16 or newer)
- A `clientId`, approved scopes, and an HTTPS `redirectUri`. See
  [Getting started](https://docs.digital.gov.krd/software-development/04-interoperability/12-krdpass-getting-started.html).

## Install

Distributed by Git only, not through a package registry. Prefer Swift Package Manager:
the CocoaPods trunk goes read-only in December 2026, so SPM is the path we will keep
supporting.

Swift Package Manager, via `File > Add Package Dependencies...` or `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/ditkrg/krdpass-auth-sdk-ios.git", exact: "1.6.0")
]
```

CocoaPods, via your `Podfile`:

```ruby
pod 'KrdpassAuth', :git => 'https://github.com/ditkrg/krdpass-auth-sdk-ios.git', :tag => 'v1.6.0'
```

## Platform setup

The redirect arrives as a Universal Link, so you need two things.

**1. The Associated Domains capability**, with `applinks:<your-redirect-host>` for your
redirect URI's host.

**2. A handler that forwards the incoming URL to the SDK.** In SwiftUI, one modifier wires
both the `.onOpenURL` and Universal Link paths. It takes a non-optional instance, so keep
the one `initialize` returns:

```swift
@main
struct MyApp: App {
    private let auth = KrdpassAuth.initialize(config) // config as in Quickstart

    var body: some Scene {
        WindowGroup {
            ContentView().withKrdpassDeepLinkHandling(auth)
        }
    }
}
```

In a UIKit `AppDelegate`, forward the `NSUserActivity` continuation:

```swift
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
```

Add the `open url:` handler as well only if you also register a custom URL scheme.

Without this, sign-in appears to hang: KRDPASS completes and returns to your app, and the
result never reaches the SDK.

## Quickstart

**1. Initialize once**, at app start. Keep the returned instance; `KrdpassAuth.shared` is
the same object but optional, so `KrdpassAuth.shared?.signIn { ... }` silently does nothing
if you have not initialized yet.

```swift
import KrdpassAuth

let config = KrdpassConfig(
    clientId: "your-client-id",
    redirectUri: "https://auth.your-app.example.com/callback", // HTTPS Universal Link
    environment: .production
)
let auth = KrdpassAuth.initialize(config)
```

**2. Sign in.** Your backend runs PAR and the token exchange; the SDK launches KRDPASS and
returns the authorization code. PKCE and `state` are yours: generate both in the app, send
only the `codeChallenge` and the `state` to your backend, and hold the `codeVerifier` until
the exchange. Pass that same `state` back into `authenticate`, or the SDK fails closed with
`invalid_request`.

```swift
let pkce = try auth.generatePkcePair()
let state = try auth.generateState()

// Your backend runs the PAR with pkce.codeChallenge and state, and returns the request_uri.
let requestUri = try await yourBackend.getRequestUri(
    codeChallenge: pkce.codeChallenge, state: state)

auth.authenticate(requestUri: requestUri, state: state) { result in
    switch result {
    case .success(let response):
        break // send response.code + pkce.codeVerifier + response.state to your backend
    case .cancelled:
        break // user came back without finishing; usually no UI needed
    case .timeout:
        break // offer retry
    case .busy:
        break // ignore or queue
    case .error(let error):
        // A cancellation KRDPASS reports on the redirect lands here with
        // error.error == "cancelled", not in the .cancelled case above.
        break // error.error, error.errorDescription, error.installUrl
    }
}
```

The client-only `signIn` API ships but needs a public client, which is not currently issued
to any integration. Use the flow above.

### Logging

Nothing is logged until you install a logger. Tokens, authorization codes and PKCE values
are redacted before they reach it.

```swift
auth.logger = MyLogger() // any type conforming to KrdpassLogger
```

### Injecting a URLSession

`initialize(_:urlSession:)` accepts a `URLSession`, used for every request the SDK makes:
PAR, token exchange, userinfo, refresh, revoke and the JWKS fetch. Supply one if you pin
certificates or route through a proxy.

## Error handling

Every error code, what emits it, and how to handle it:
[Testing and go-live](https://docs.digital.gov.krd/software-development/04-interoperability/14-krdpass-testing-and-go-live.html).

`invalid_redirect` is defined for cross-SDK parity but this SDK never delivers it: a callback
that does not match the configured endpoint leaves `handle(_:)` returning false, and the flow
ends as `cancelled` once the foreground watcher sees the app return without a result.

## Tokens and identity

`getUserInfo`, `refreshTokens`, `revokeToken`, `verifyToken` and `decodeTokenUnverified` are
`async` methods on `KrdpassAuth`. Scopes, claims and token handling rules:
[Reference](https://docs.digital.gov.krd/software-development/04-interoperability/15-krdpass-reference.html).

The SDK never persists tokens. Storage requirements:
[Token storage](https://github.com/ditkrg/krdpass-auth-samples/blob/main/docs/TOKEN-STORAGE.md).

## Samples

Runnable apps for all five platforms, plus a reference backend:
[krdpass-auth-samples](https://github.com/ditkrg/krdpass-auth-samples).

## Development

```bash
swift format lint --strict --recursive Sources Tests
./scripts/test_ios.sh
```

## License

MIT. See [LICENSE](LICENSE).
