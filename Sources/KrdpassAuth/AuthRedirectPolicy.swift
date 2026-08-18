import Foundation

/// The redirect-response policy ``KrdpassAuth/handle(_:)`` applies once the callback URL has
/// been parsed: CSRF state matching, the RFC 9207 issuer check and error canonicalization.
extension KrdpassAuth {

    /// Pure auth-result decision.
    ///
    /// Fail-closed (RFC 6749 Section 10.12): a code or error is accepted only with a returned
    /// state equal to the one we sent. RFC 9207: a code carrying an `iss` that is not
    /// `expectedIssuer` is rejected as a mix-up attack; an absent `iss` is accepted (optional,
    /// and CAS omits it on error responses). A response with both `code` and `error` never
    /// reaches here: ``KrdpassAuth/handle(_:)`` returns false for it and leaves the URL to other
    /// handlers. The flow ends as `cancelled` once ``ForegroundReturnWatcher`` sees the app come
    /// back without a result.
    nonisolated static func decideAuthResult(
        code: String?,
        returnedState: String?,
        error: String?,
        errorDescription: String?,
        returnedIss: String?,
        expectedState: String?,
        expectedIssuer: String?
    ) -> AuthResult {
        if let error = error {
            guard isStateMatch(expectedState, returnedState) else {
                return .error(.stateMismatch())
            }
            // Every cancel-class code collapses to the canonical `cancelled`, but stays an ERROR:
            // `.cancelled` is reserved for a flow that ended with no response at all.
            let canonicalError = isCancellationError(error) ? "cancelled" : error
            return .error(
                AuthError(error: canonicalError, errorDescription: errorDescription?.bounded()))
        }

        if let code = code {
            guard isStateMatch(expectedState, returnedState) else {
                return .error(.stateMismatch())
            }
            // Exact string equality, same convention as the id_token iss claim.
            if let returnedIss = returnedIss, returnedIss != expectedIssuer {
                return .error(.issuerMismatch())
            }
            return .success(AuthResponse(code: code, state: returnedState))
        }

        return .error(AuthError.noCode)
    }

    /// Fails closed on a state we never recorded, never got back, or that does not match.
    private nonisolated static func isStateMatch(_ expected: String?, _ returned: String?) -> Bool {
        guard let expected = expected, !expected.isEmpty,
            let returned = returned, !returned.isEmpty
        else { return false }
        return constantTimeEquals(returned, expected)
    }

    private nonisolated static func isCancellationError(_ error: String) -> Bool {
        return error == "access_denied" || error == "cancelled" || error == "user_cancelled"
            || error == "login_required" || error == "consent_denied"
    }

    /// Constant-time string comparison.
    nonisolated static func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let lhsBytes = Array(lhs.utf8)
        let rhsBytes = Array(rhs.utf8)
        guard lhsBytes.count == rhsBytes.count else { return false }

        var diff: UInt8 = 0
        for i in 0..<lhsBytes.count {
            diff |= lhsBytes[i] ^ rhsBytes[i]
        }
        return diff == 0
    }
}
