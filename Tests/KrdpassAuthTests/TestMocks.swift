import Foundation
import XCTest

@testable import KrdpassAuth

/// A mock URL opener that allows checking what URL was opened and simulating success/failure.
internal class MockUrlOpener: UrlOpener {
    var onOpen: ((URL) -> Void)?
    var simulateSuccess: Bool = true

    func open(
        _ url: URL, options: [UIApplication.OpenExternalURLOptionsKey: Any],
        completion: (@MainActor (Bool) -> Void)?
    ) {
        onOpen?(url)
        DispatchQueue.main.async {
            completion?(self.simulateSuccess)
        }
    }
}

/// A mock URLProtocol backed by a queue of responses, so a test can script a multi-request flow
/// (PAR, then token exchange, then JWKS) in order.
internal class MockURLProtocol: URLProtocol {
    struct MockResponse {
        let data: Data
        let statusCode: Int
        let headers: [String: String]
    }

    // nonisolated(unsafe): these are manually synchronized by `lock` below (the compiler can't see
    // the lock-guarding, so we assert the safety it can't prove).
    nonisolated(unsafe) static var responseQueue: [MockResponse] = []
    nonisolated(unsafe) static var lastRequest: URLRequest?
    /// Body of `lastRequest`, captured here rather than read back by the tests: URLSession turns
    /// an `httpBody` into a one-shot `httpBodyStream`, which only `startLoading` can still read.
    nonisolated(unsafe) static var lastRequestBody: String = ""
    private static let lock = NSRecursiveLock()

    static func setResponse(_ data: Data, statusCode: Int = 200, headers: [String: String] = [:]) {
        lock.lock()
        defer { lock.unlock() }
        responseQueue = [MockResponse(data: data, statusCode: statusCode, headers: headers)]
    }

    static func enqueueResponse(
        _ data: Data, statusCode: Int = 200, headers: [String: String] = [:]
    ) {
        lock.lock()
        defer { lock.unlock() }
        responseQueue.append(MockResponse(data: data, statusCode: statusCode, headers: headers))
    }

    override class func canInit(with request: URLRequest) -> Bool {
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }

    override func startLoading() {
        Self.lock.lock()
        Self.lastRequest = request
        Self.lastRequestBody = Self.bodyString(of: request)

        guard !Self.responseQueue.isEmpty else {
            Self.lock.unlock()
            let error = NSError(
                domain: "MockError", code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "No mock response enqueued for request: \(request.url?.absoluteString ?? "unknown")"
                ])
            client?.urlProtocol(self, didFailWithError: error)
            return
        }

        let response = Self.responseQueue.removeFirst()
        Self.lock.unlock()

        let httpResponse = HTTPURLResponse(
            url: request.url!,
            statusCode: response.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: response.headers
        )!

        client?.urlProtocol(self, didReceive: httpResponse, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: response.data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {
    }

    private static func bodyString(of request: URLRequest) -> String {
        if let body = request.httpBody {
            return String(data: body, encoding: .utf8) ?? ""
        }
        guard let stream = request.httpBodyStream else { return "" }
        stream.open()
        let bufferSize = 1024
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer {
            buffer.deallocate()
            stream.close()
        }
        var data = Data()
        while stream.hasBytesAvailable {
            let read = stream.read(buffer, maxLength: bufferSize)
            guard read > 0 else { break }
            data.append(buffer, count: read)
        }
        return String(data: data, encoding: .utf8) ?? ""
    }
}
