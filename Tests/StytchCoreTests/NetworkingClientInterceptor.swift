import Foundation
@preconcurrency import SwiftyJSON
import XCTest
@testable import StytchCore

final class NetworkingClientInterceptor: NetworkingClient {
    // Requests arrive concurrently (SDK code fires telemetry from detached
    // tasks), so every access to these arrays must hold the lock — unguarded
    // mutation was intermittently crashing the whole test runner
    // ("Array replace: subrange extends past the end").
    private let lock = NSLock()
    private var _requests: [URLRequest] = []
    private var responses: [Result<Data, Error>] = []

    var requests: [URLRequest] {
        lock.withLock { _requests }
    }

    func configureDFP(dfpEnabled _: Bool, dfpAuthMode _: DFPProtectedAuthMode?) {}

    func handleRequest(request: URLRequest, useDFPPA _: Bool) async throws -> (Data, HTTPURLResponse) {
        let next: Result<Data, Error> = try lock.withLock {
            if request.url?.absoluteString.contains("/v1/events") != nil {
                responses.append(.success(try Current.jsonEncoder.encode(AuthenticateResponse.mock)).map { $0.surroundInDataJSONContainer() })
            }
            _requests.append(request)
            return responses.removeFirst()
        }

        switch next {
        case let .success(data):
            return try (
                data,
                XCTUnwrap(.init(url: XCTUnwrap(request.url), statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:]))
            )
        case let .failure(error):
            throw error
        }
    }

    func responses(@ResponsesBuilder _ build: () -> ResponsesContainer) {
        let built = build().responses.map { result in
            result.flatMap {
                do {
                    return .success(try Current.jsonEncoder.encode($0)).map { $0.surroundInDataJSONContainer() }
                } catch {
                    XCTFail("Unable to serialize response data")
                    return .failure(error)
                }
            }
        }
        lock.withLock { responses = built }
    }

    func reset() {
        lock.withLock {
            _requests = []
            responses = []
        }
    }
}

private extension Data {
    func surroundInDataJSONContainer() -> Data {
        // Surround in a data json container {"data":<existing contents>}
        var result: [UInt8] = [123, 34, 100, 97, 116, 97, 34, 58, 125]
        result.insert(contentsOf: self, at: 8)
        return .init(result)
    }
}

@resultBuilder
enum ResponsesBuilder {
    static func buildPartialBlock(
        first: Success
    ) -> ResponsesContainer {
        first.responses
    }

    static func buildPartialBlock(
        first: Failure
    ) -> ResponsesContainer {
        first.responses
    }

    static func buildPartialBlock<T: Codable>(
        first: T
    ) -> ResponsesContainer {
        Success { first }.responses
    }

    static func buildPartialBlock<T: Error>(
        first: T
    ) -> ResponsesContainer {
        Failure { first }.responses
    }

    static func buildPartialBlock(
        accumulated: ResponsesContainer,
        next: Success
    ) -> ResponsesContainer {
        .init(responses: accumulated.responses + buildPartialBlock(first: next).responses)
    }

    static func buildPartialBlock(
        accumulated: ResponsesContainer,
        next: Failure
    ) -> ResponsesContainer {
        .init(responses: accumulated.responses + buildPartialBlock(first: next).responses)
    }

    static func buildPartialBlock<T: Codable>(
        accumulated: ResponsesContainer,
        next: T
    ) -> ResponsesContainer {
        .init(responses: accumulated.responses + buildPartialBlock(first: next).responses)
    }

    static func buildPartialBlock<T: Error>(
        accumulated: ResponsesContainer,
        next: T
    ) -> ResponsesContainer {
        .init(responses: accumulated.responses + buildPartialBlock(first: next).responses)
    }
}

struct Failure {
    let responses: ResponsesContainer

    init(@FailureResponsesBuilder _ build: () -> ResponsesContainer) {
        responses = build()
    }
}

@resultBuilder
enum FailureResponsesBuilder {
    static func buildPartialBlock<T: Error>(first: T) -> ResponsesContainer {
        .init(responses: [.failure(first)])
    }

    static func buildPartialBlock<T: Error>(accumulated: ResponsesContainer, next: T) -> ResponsesContainer {
        .init(responses: accumulated.responses + buildPartialBlock(first: next).responses)
    }
}

struct Success {
    let responses: ResponsesContainer

    init(@SuccessResponsesBuilder _ build: () -> ResponsesContainer) {
        responses = build()
    }
}

@resultBuilder
enum SuccessResponsesBuilder {
    static func buildPartialBlock<T: Codable>(first: T) -> ResponsesContainer {
        .init(responses: [.success(first)])
    }

    static func buildPartialBlock<T: Codable>(accumulated: ResponsesContainer, next: T) -> ResponsesContainer {
        .init(responses: accumulated.responses + buildPartialBlock(first: next).responses)
    }
}

struct ResponsesContainer {
    let responses: [Result<any Codable, Error>]
}

struct ExpectedRequest<T> {
    let parameters: T
    let urlString: String
    let body: JSON
}
