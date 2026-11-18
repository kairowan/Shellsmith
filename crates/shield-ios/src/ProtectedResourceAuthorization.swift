import CryptoKit
import DeviceCheck
import Foundation
import Security

public enum ShellsmithResourceError: Error {
    case unavailable
    case denied
    case pendingApproval
    case invalidResponse
}

@available(iOS 14.0, *)
public enum ShellsmithProtectedResources {
    private static let authorization = ResourceAuthorization()

    public static func data(_ id: String) async throws -> Data {
        try await data(id, range: nil)
    }

    public static func observeEnvironment(_ observer: @Sendable ([String: String]) -> Void) {
        observer(["version": "1", "source": "ios", "phase": "lifecycle",
                  "result": ShellsmithRuntime.resourceSignal()])
    }

    public static func data(_ id: String, range: Range<Int>?, blockRuntimeGroups: Set<String> = [],
                            observer: (@Sendable ([String: String]) -> Void)? = nil) async throws -> Data {
        try await authorizedData(id, range: range, blockRuntimeGroups: blockRuntimeGroups, observer: observer).0
    }

    static func authorizedData(_ id: String, range: Range<Int>?, blockRuntimeGroups: Set<String>,
                               observer: (@Sendable ([String: String]) -> Void)? = nil) async throws -> (Data, TimeInterval) {
        guard id.range(of: #"\A[a-z0-9_-]{1,64}\z"#, options: .regularExpression) != nil,
              let directory = Bundle.module.resourceURL?.appendingPathComponent("shellsmith-resources") else {
            throw ShellsmithResourceError.unavailable
        }
        let indexURL = directory.appendingPathComponent("index.json")
        let indexData = try Data(contentsOf: indexURL)
        guard indexData.count <= 256 * 1024 else { throw ShellsmithResourceError.invalidResponse }
        let index = try JSONDecoder().decode(ResourceIndex.self, from: indexData)
        guard index.version == 1, let row = index.resources[id], let token = index.groups[row.group],
              let bundleId = Bundle.main.bundleIdentifier,
              index.app_id.split(separator: ".", maxSplits: 1).last == Substring(bundleId),
              let build = hexBytes(index.build_id), build.count == 16 else {
            throw ShellsmithResourceError.invalidResponse
        }
        let readId = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let block = blockRuntimeGroups.contains(row.group)
        func report(_ phase: String, _ result: String, _ authorizationId: String? = nil) {
            guard let observer else { return }
            var event = ["version": "1", "source": "ios", "phase": phase, "group": row.group,
                         "read_id": readId, "result": result]
            event["authorization_id"] = authorizationId
            observer(event)
        }
        func allowsRead(_ signal: String) -> Bool {
            !block || (signal != "debugger" && signal != "runtime_integrity")
        }
        if observer != nil || block {
            let signal = ShellsmithRuntime.resourceSignal()
            report("environment", signal)
            guard allowsRead(signal) else {
                report("read", "local_policy_denied")
                throw ShellsmithResourceError.denied
            }
        }
        let lease: ResourceLease
        do {
            let (value, result) = try await authorization.obtain(index: index, token: token, group: row.group)
            lease = value
            report("authorization", result, lease.traceId)
        } catch let failure as ResourceAuthorizationFailure {
            let result: String
            switch failure.cause {
            case ShellsmithResourceError.pendingApproval: result = "pending"
            case ShellsmithResourceError.denied: result = "denied"
            case ResourceTransportError.serverUnavailable: result = "server_unavailable"
            case ResourceTransportError.rateLimited: result = "rate_limited"
            case is URLError: result = "transport_error"
            default: result = "unavailable"
            }
            report("authorization", result, failure.traceId)
            if failure.cause is ResourceTransportError { throw ShellsmithResourceError.invalidResponse }
            throw failure.cause
        }
        try Task.checkCancellation()
        let file = try FileHandle(forReadingFrom: directory.appendingPathComponent(id + ".ssr"))
        defer { try? file.close() }
        var content = Data()
        do {
            try ProtectedResourceReader.read(from: file, build: build, group: row.group,
                resource: id, version: row.version, key: lease.key, range: range,
                authorized: {
                    ProcessInfo.processInfo.systemUptime < lease.until && !Task.isCancelled
                        && (!block || allowsRead(ShellsmithRuntime.resourceSignal()))
                }) { content.append($0) }
            report("read", "verified", lease.traceId)
        } catch {
            let result: String
            switch error {
            case ProtectedResourceReadError.authentication: result = "authentication_failed"
            case ProtectedResourceReadError.expired: result = "policy_or_lease_ended"
            default: result = "invalid"
            }
            report("read", result, lease.traceId)
            throw error
        }
        return (content, lease.until)
    }

    private static func hexBytes(_ text: String) -> Data? {
        let bytes = Array(text.utf8)
        guard bytes.count == 32 else { return nil }
        var result = Data()
        for index in stride(from: 0, to: 32, by: 2) {
            guard let byte = UInt8(String(decoding: bytes[index..<index + 2], as: UTF8.self), radix: 16) else { return nil }
            result.append(byte)
        }
        return result
    }
}

private struct ResourceIndex: Decodable, Sendable {
    struct Row: Decodable, Sendable { let group: String; let version: UInt32 }
    let version: UInt32
    let build_id: String
    let app_id: String
    let environment: String
    let server_url: String
    let groups: [String: String]
    let resources: [String: Row]
}

private struct ResourceLease: Sendable {
    let key: Data
    let until: TimeInterval
    let traceId: String
}

private struct ResourceAuthorizationFailure: Error {
    let cause: Error
    let traceId: String
}

private enum ResourceTransportError: Error { case serverUnavailable, rateLimited }

@available(iOS 14.0, *)
private actor ResourceAuthorization {
    private var cached: [String: ResourceLease] = [:]
    private var pending: [String: Task<ResourceLease, Error>] = [:]
    private var previous: Task<Void, Never>?

    func obtain(index: ResourceIndex, token: String, group: String) async throws -> (ResourceLease, String) {
        try Task.checkCancellation()
        if let lease = cached[token], lease.until > ProcessInfo.processInfo.systemUptime { return (lease, "cached") }
        cached[token] = nil
        if let existing = pending[token] { return (try await existing.value, "coalesced") }
        // 同一设备的所有断言按生成顺序提交，防止跨组并发把旧计数送到服务端。
        let preceding = previous
        let traceId = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let task = Task {
            await preceding?.value
            do { return try await Self.request(index: index, token: token, group: group, traceId: traceId) }
            catch { throw ResourceAuthorizationFailure(cause: error, traceId: traceId) }
        }
        previous = Task { _ = try? await task.value }
        pending[token] = task
        defer { pending[token] = nil }
        let lease = try await task.value
        cached[token] = lease
        let delay = max(0, lease.until - ProcessInfo.processInfo.systemUptime)
        Task {
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            if cached[token]?.until == lease.until { cached[token] = nil }
        }
        return (lease, "granted")
    }

    private static func request(index: ResourceIndex, token: String, group: String, traceId: String) async throws -> ResourceLease {
        guard ShellsmithAppAttest.isSupported else { throw ShellsmithResourceError.unavailable }
        let keyID = try await ShellsmithAppAttest.resourceKeyId(appId: index.app_id, environment: index.environment)
        guard let keyIDBytes = Data(base64Encoded: keyID), keyIDBytes.count == 32 else { throw ShellsmithResourceError.invalidResponse }
        let keyField = keyIDBytes.base64EncodedString()
        guard let privateKey = SecKeyCreateRandomKey([
            kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048
        ] as CFDictionary, nil), let publicKey = SecKeyCopyPublicKey(privateKey),
        let rsa = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw ShellsmithResourceError.unavailable
        }
        // Security 返回 PKCS#1；BYOS 统一使用带 rsaEncryption 标识的 SPKI 结构。
        let algorithm = Data([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00])
        let responseKey = der(0x30, algorithm + der(0x03, Data([0]) + rsa)).base64EncodedString()
        var body = ["token_id": token, "build_id": index.build_id, "resource_group": group,
                    "key_id": keyField, "response_public_key": responseKey]
        let started = ProcessInfo.processInfo.systemUptime
        let challengeResponse: Challenge = try await post(index.server_url, "challenge", body, traceId)
        let action = challengeResponse.action
        let challenge = challengeResponse.challenge
        guard (action == "assert" || action == "attest"), challenge.count == 96,
              challenge.range(of: #"\A[A-Za-z0-9_-]+\z"#, options: .regularExpression) != nil else {
            throw ShellsmithResourceError.invalidResponse
        }
        let context = ["shellsmith-ios-resource-v1", index.app_id, index.environment, action,
                       token, index.build_id, group, keyField, responseKey, challenge].joined(separator: "\n")
        let digest = Data(SHA256.hash(data: Data(context.utf8)))
        let proof: Data
        do {
            if action == "attest" {
                proof = try await ShellsmithAppAttest.attestKey(keyID, clientDataHash: digest)
            } else {
                proof = try await ShellsmithAppAttest.generateAssertion(keyID, clientDataHash: digest)
            }
        } catch let error as DCError where error.code == .invalidKey {
            try ShellsmithAppAttest.forgetResourceKey(appId: index.app_id, environment: index.environment)
            throw ShellsmithResourceError.unavailable
        }
        body["action"] = action
        body["challenge"] = challenge
        body["proof"] = proof.base64EncodedString()
        let response: LeaseResponse = try await post(index.server_url, "fetch", body, traceId)
        if response.status == "pending" { throw ShellsmithResourceError.pendingApproval }
        guard action == "assert", response.status == "granted", let ttl = response.ttl_seconds,
              (1...60).contains(ttl), let envelope = response.wrapped_ikm,
              let wrapped = Data(base64Encoded: envelope), wrapped.count == 256,
              let decrypted = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA256, wrapped as CFData, nil) as Data?,
              decrypted.count == 64, decrypted.prefix(32) == digest else {
            throw ShellsmithResourceError.invalidResponse
        }
        let expires = started + Double(ttl)
        guard expires > ProcessInfo.processInfo.systemUptime else { throw ShellsmithResourceError.denied }
        return ResourceLease(key: Data(decrypted.suffix(32)), until: expires, traceId: traceId)
    }

    private struct Challenge: Decodable { let action: String; let challenge: String }
    private struct LeaseResponse: Decodable { let status: String; let wrapped_ikm: String?; let ttl_seconds: Int? }

    private static func der(_ tag: UInt8, _ body: Data) -> Data {
        let count = body.count
        if count < 128 { return Data([tag, UInt8(count)]) + body }
        if count < 256 { return Data([tag, 0x81, UInt8(count)]) + body }
        return Data([tag, 0x82, UInt8(count >> 8), UInt8(truncatingIfNeeded: count)]) + body
    }

    private static func post<T: Decodable>(_ endpoint: String, _ operation: String, _ body: [String: String],
                                           _ traceId: String) async throws -> T {
        guard let url = URL(string: endpoint + "/v1/ios-resource-keys/" + operation),
              url.scheme == "https", url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else {
            throw ShellsmithResourceError.invalidResponse
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(traceId, forHTTPHeaderField: "X-Shellsmith-Request-ID")
        request.httpBody = try JSONEncoder().encode(body)
        let session = URLSession(configuration: .ephemeral, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let data: Data = try await withCheckedThrowingContinuation { continuation in
            session.dataTask(with: request) { data, response, error in
                if let error { continuation.resume(throwing: error); return }
                if (response as? HTTPURLResponse)?.statusCode == 403 {
                    continuation.resume(throwing: ShellsmithResourceError.denied); return
                }
                let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                if status == 429 { continuation.resume(throwing: ResourceTransportError.rateLimited); return }
                if (500...599).contains(status) { continuation.resume(throwing: ResourceTransportError.serverUnavailable); return }
                guard status == 200, let data, data.count <= 4096 else {
                    continuation.resume(throwing: ShellsmithResourceError.invalidResponse); return
                }
                continuation.resume(returning: data)
            }.resume()
        }
        return try JSONDecoder().decode(T.self, from: data)
    }
}

private final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
