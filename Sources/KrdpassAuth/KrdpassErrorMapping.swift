import Foundation

extension String {
    /// A provider's `error_description` reaches the app verbatim;
    /// cap it at enough to diagnose with, far short of a dumped page or stack.
    func bounded(max: Int = 256) -> String {
        count <= max ? self : String(prefix(max)) + "...[truncated]"
    }
}

/// Translation of the SDK's internal failures onto ``KrdpassError``, the single error contract
/// its public entry points throw.
extension KrdpassAuth {

    /// Map a caught error onto the public ``KrdpassError``. `catch` yields `any Error` with no
    /// `Sendable` guarantee; anything not already Sendable is re-wrapped so its message survives.
    static func asKrdpassError(_ error: Error) -> KrdpassError {
        if let krdpassError = error as? KrdpassError { return krdpassError }
        if let casError = error as? CasException { return .networkError(casError) }
        if let urlError = error as? URLError { return .networkError(urlError) }
        return .networkError(CasException(message: error.localizedDescription))
    }

    /// Classify a verifier failure into three codes:
    /// `invalid_id_token` (signature, claims or exp), `network_error` (JWKS fetch failed, so a
    /// retry may help), and `verification_failed` for anything else. The underlying reason
    /// carries through verbatim: it is the only diagnostic a caller of a verify-only API has.
    nonisolated static func verifyErrorToKrdpassError(_ error: Error) -> KrdpassError {
        // Already the public model: re-wrapping would rename its code.
        if let krdpassError = error as? KrdpassError { return krdpassError }

        let code: String
        switch error {
        case TokenVerificationError.jwksFetchFailed:
            code = "network_error"
        case is TokenVerificationError:
            code = "invalid_id_token"
        case is URLError:
            code = "network_error"
        default:
            code = "verification_failed"
        }
        return .authenticationFailed(
            "ID token verification failed: \(error.localizedDescription)", code: code)
    }

    /// Translate the internal ``CasException`` thrown by the token calls into the public
    /// ``KrdpassError``. The retryable/permanent split matters: `network_error` is the retryable
    /// code, and a 4xx must not look retryable.
    nonisolated static func casErrorToKrdpassError(_ error: CasException) -> KrdpassError {
        error.isRetryable
            ? .networkError(error)
            : .authenticationFailed(error.localizedDescription, code: nil)
    }

    /// Run a CAS call, translating every failure (CasException, URLError, JSON parse errors,
    /// cancellation) into the public ``KrdpassError``. Transport-level failures stay retryable
    /// `.networkError`; anything else becomes `.authenticationFailed` with `code: nil`.
    /// Messages carry through verbatim.
    static func translatingCasErrors<T: Sendable>(
        _ body: () async throws -> T
    ) async throws -> T {
        do {
            return try await body()
        } catch let error as CasException {
            throw casErrorToKrdpassError(error)
        } catch let error as KrdpassError {
            throw error
        } catch let error as URLError {
            throw KrdpassError.networkError(error)
        } catch let error as CancellationError {
            // CancellationError is not Sendable, so the message rides in the SDK's own carrier.
            throw KrdpassError.networkError(CasException(message: error.localizedDescription))
        } catch {
            throw KrdpassError.authenticationFailed(error.localizedDescription, code: nil)
        }
    }
}
