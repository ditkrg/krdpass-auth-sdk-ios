# ``KrdpassAuth``

Sign in with KRDPASS for native iOS apps.

## Overview

The SDK hands off to the installed KRDPASS identity app over a Universal Link and receives the
result back at your HTTPS redirect URI. There is no browser or WebView flow, and if KRDPASS is
not installed the attempt fails closed with `provider_not_installed`.

Two flows are available. ``KrdpassAuth/signIn(scopes:timeout:)`` is client-only: the SDK runs
PKCE, PAR and the token exchange itself. ``KrdpassAuth/authenticate(requestUri:state:timeout:)``
is server-mediated: your backend runs PAR and the token exchange, and the SDK returns the
authorization code.

Every public entry point throws ``KrdpassError``.

## Topics

### Setup

- ``KrdpassAuth/initialize(_:urlSession:)``
- ``KrdpassConfig``
- ``KrdpassEnvironment``
- ``KrdpassScopes``

### Signing in

- ``KrdpassAuth/signIn(scopes:timeout:)``
- ``KrdpassAuth/authenticate(requestUri:state:timeout:)``
- ``KrdpassAuth/generatePkcePair()``
- ``KrdpassAuth/generateState()``
- ``KrdpassAuth/cancelPendingAuthentication(timeout:)``

### Receiving the redirect

- ``KrdpassAuth/canHandle(_:)``
- ``KrdpassAuth/handle(_:)``
- ``SwiftUI/View/withKrdpassDeepLinkHandling(_:)``

### Results and errors

- ``KrdpassTokenResult``
- ``AuthResult``
- ``AuthResponse``
- ``AuthError``
- ``KrdpassError``

### Tokens and user info

- ``KrdpassAuth/getUserInfo(accessToken:)``
- ``KrdpassAuth/refreshTokens(refreshToken:scope:)``
- ``KrdpassAuth/revokeToken(token:tokenTypeHint:)``
- ``KrdpassAuth/verifyToken(idToken:clockSkew:)``
- ``KrdpassAuth/decodeTokenUnverified(_:)``
- ``KrdpassUserInfo``
- ``JSONValue``

### Logging

- ``KrdpassLogger``
