import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// The challenge/verify client: a POST to the challenge endpoint and the
/// provider-shaped siteverify body builder. Verification itself is a
/// server-to-server call; the app submits the token with its own
/// authenticated request and the backend runs siteverify.
public struct KiwiClient {
    public let endpoint: URL
    public var session: URLSession
    public var sitekey: String?

    public init(endpoint: URL, sitekey: String? = nil, session: URLSession = .shared) {
        self.endpoint = endpoint
        self.sitekey = sitekey
        self.session = session
    }

    public enum ClientError: Error, Equatable {
        case badStatus(Int)
        case malformed(String)
    }

    /// POST the challenge request and parse (not validate) the document;
    /// `KiwiSolver.validate` enforces the contract at solve time.
    public func fetchChallenge(
        scope: String, algorithm: String? = nil, requestBinding: String? = nil
    ) async throws -> KiwiChallenge {
        var body: [String: String] = ["scope": scope]
        if let algorithm { body["algorithm"] = algorithm }
        if let sitekey { body["sitekey"] = sitekey }
        if let requestBinding { body["request_binding"] = requestBinding }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw ClientError.badStatus(status)
        }
        do {
            return try JSONDecoder().decode(KiwiChallenge.self, from: data)
        } catch {
            throw ClientError.malformed("the challenge response is not a challenge document")
        }
    }

    /// The provider-shaped siteverify request body (secret, response,
    /// optional remoteip), the same document the Rust solver builds.
    public static func siteverifyBody(secret: String, response: String, remoteip: String? = nil) throws -> Data {
        var body: [String: String] = ["secret": secret, "response": response]
        if let remoteip { body["remoteip"] = remoteip }
        return try JSONEncoder().encode(body)
    }
}
