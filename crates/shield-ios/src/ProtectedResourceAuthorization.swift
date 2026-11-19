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

    static func startRiskEvents() {
        Task { await authorization.restoreRisk() }
    }

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
                    ProtectedResourceClock.now < lease.until && !Task.isCancelled
                        && ShellsmithRuntime.resourceSignal() != "authorization_revoked"
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

struct ResourceIndex: Decodable, Sendable {
    struct Row: Decodable, Sendable { let group: String; let version: UInt32 }
    let version: UInt32
    let build_id: String
    let app_id: String
    let environment: String
    let server_url: String
    let groups: [String: String]
    let resources: [String: Row]
    let key_source: String?
    let risk_protocol: Int?
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
    private var riskScopes: [String: RiskScope] = [:]
    private var riskObserver: NSObjectProtocol?
    private var riskRetry: Task<Void, Never>?
    private var nextRiskChallenge: Int64 = 0

    func restoreRisk() {
        guard let directory = Bundle.module.resourceURL?.appendingPathComponent("shellsmith-resources"),
              let data = try? Data(contentsOf: directory.appendingPathComponent("index.json")), data.count <= 256 * 1024,
              let index = try? JSONDecoder().decode(ResourceIndex.self, from: data), index.version == 1,
              index.key_source == "byos", index.risk_protocol == 1,
              let bundleID = Bundle.main.bundleIdentifier,
              index.app_id.split(separator: ".", maxSplits: 1).last == Substring(bundleID),
              FileManager.default.fileExists(atPath: Self.riskDirectory.path) else { return }
        let preceding = previous
        let task = Task {
            await preceding?.value
            guard let keyID = try? await ShellsmithAppAttest.resourceKeyId(appId: index.app_id, environment: index.environment) else { return }
            for (group, token) in index.groups {
                activateRisk(index: index, token: token, group: group, keyID: keyID, granted: false)
            }
        }
        previous = task
    }

    private static var riskDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("shellsmith-risk-v1", isDirectory: true)
    }

    private func activateRisk(index: ResourceIndex, token: String, group: String, keyID: String, granted: Bool,
                              protocolVersion: Int = 1, authorizationVersion: Int? = nil) {
        guard index.key_source == "byos", index.risk_protocol == 1,
              let identity = Data(base64Encoded: keyID), identity.count == 32 else { return }
        var scope = RiskScope(endpoint: index.server_url, token: token, build: index.build_id,
                              group: group, keyID: keyID, installation: RiskEvent.hex(identity))
        let allowed = Set(index.groups.map { pair in
            RiskScope(endpoint: index.server_url, token: pair.value, build: index.build_id, group: pair.key,
                      keyID: keyID, installation: scope.installation).binding + ".json"
        })
        if let files = try? FileManager.default.contentsOfDirectory(at: Self.riskDirectory, includingPropertiesForKeys: nil) {
            for file in files where !allowed.contains(file.lastPathComponent) { try? FileManager.default.removeItem(at: file) }
        }
        let obsolete = Set(riskScopes.values.filter { $0.installation != scope.installation }.map(\.keyID))
        for oldKey in obsolete { invalidateRisk(oldKey) }
        let binding = scope.binding
        if var existing = riskScopes[binding] {
            if granted {
                existing.protocolVersion = protocolVersion
                existing.authorizationVersion = max(existing.authorizationVersion ?? -1, authorizationVersion ?? -1)
                riskScopes[binding] = existing
                _ = persistRisk(binding)
            }
            return
        }
        guard riskScopes.count < 64 else { return }
        let path = Self.riskDirectory.appendingPathComponent(binding + ".json")
        if let bytes = try? Data(contentsOf: path), bytes.count <= 128 * 1024,
           let saved = try? JSONDecoder().decode(RiskScope.self, from: bytes),
           saved.binding == binding, saved.keyID == keyID, saved.queue.count <= 16 {
            scope = saved
        } else if !granted { return }
        if granted {
            scope.protocolVersion = protocolVersion
            scope.authorizationVersion = max(scope.authorizationVersion ?? -1, authorizationVersion ?? -1)
        }
        riskScopes[binding] = scope
        guard persistRisk(binding) else { riskScopes[binding] = nil; return }
        if riskObserver == nil {
            riskObserver = NotificationCenter.default.addObserver(
                forName: Notification.Name("dev.shellsmith.threat-detected"), object: nil, queue: nil
            ) { [weak self] notification in
                guard let code = notification.userInfo?["threat"] as? String else { return }
                let detected = Int64(Date().timeIntervalSince1970)
                Task { await self?.detectedRisk(code, at: detected) }
            }
        }
        for code in ShellsmithRuntime.riskSignals() {
            detectedRisk(code, at: Int64(Date().timeIntervalSince1970))
        }
        scheduleRisk(after: 1)
    }

    private func invalidateRisk(_ keyID: String) {
        for (binding, scope) in riskScopes where scope.keyID == keyID {
            riskScopes[binding] = nil
            try? FileManager.default.removeItem(at: Self.riskDirectory.appendingPathComponent(binding + ".json"))
        }
        if riskScopes.isEmpty {
            if let observer = riskObserver { NotificationCenter.default.removeObserver(observer) }
            riskObserver = nil
            riskRetry?.cancel(); riskRetry = nil
        }
    }

    private func persistRisk(_ binding: String) -> Bool {
        do {
            guard let scope = riskScopes[binding] else { return false }
            let directory = Self.riskDirectory
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            var values = URLResourceValues(); values.isExcludedFromBackup = true
            var mutableDirectory = directory; try mutableDirectory.setResourceValues(values)
            let data = try JSONEncoder().encode(scope)
            try data.write(to: directory.appendingPathComponent(binding + ".json"), options: .atomic)
            return true
        } catch { NSLog("R_STORAGE"); return false }
    }

    private func detectedRisk(_ code: String, at timestamp: Int64) {
        guard code.range(of: #"\A[A-Za-z][A-Za-z0-9_]{0,63}\z"#, options: .regularExpression) != nil else { return }
        for binding in Array(riskScopes.keys) {
            guard var scope = riskScopes[binding] else { continue }
            let protocolVersion = scope.protocolVersion ?? 1
            let evidence = protocolVersion == 2 ? RiskEvent.iosEvidence(code) : nil
            if scope.queue.contains(where: { $0.event.detection_code == code
                && (protocolVersion == 1 || $0.event.evidence?["signal"] == evidence?["signal"]) }) { continue }
            guard scope.queue.count < 16 else { NSLog("R_QUEUE_FULL"); continue }
            let event = RiskEvent(protocol: protocolVersion, platform: "ios", token_id: scope.token, build_id: scope.build,
                resource_group: scope.group, installation_id: scope.installation,
                event_id: UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(),
                detected_at: timestamp, detection_code: code, detector_version: protocolVersion == 2 ? "2" : "1", evidence: evidence)
            scope.queue.append(RiskItem(event: event))
            riskScopes[binding] = scope
            guard persistRisk(binding) else { scheduleRisk(after: 60); continue }
        }
        scheduleRisk(after: 1)
    }

    private func scheduleRisk(after seconds: UInt64) {
        guard riskRetry == nil else { return }
        riskRetry = Task { [weak self] in
            do { try await Task.sleep(nanoseconds: seconds * 1_000_000_000) }
            catch { return }
            await self?.queueRisk()
        }
    }

    private func queueRisk() {
        riskRetry = nil
        let preceding = previous
        let task = Task {
            await preceding?.value
            await flushRisk()
        }
        // 取钥和事件从 assertion 生成到 HTTP 响应共用一条队列。
        previous = task
    }

    private func flushRisk() async {
        let now = Int64(Date().timeIntervalSince1970)
        for binding in Array(riskScopes.keys).sorted() {
            riskScopes[binding]?.queue.removeAll { now - $0.event.detected_at > 86400 }
            guard persistRisk(binding) else { scheduleRisk(after: 60); continue }
            guard let scope = riskScopes[binding], scope.next <= now,
                  let item = scope.queue.first(where: { !$0.stopped }) else { continue }
            let id = item.event.event_id
            do {
                var report = item.report
                if report == nil {
                    if now < nextRiskChallenge { riskScopes[binding]?.next = nextRiskChallenge; continue }
                    nextRiskChallenge = now + 6
                    var random = Data(count: 32)
                    guard random.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
                        throw ShellsmithResourceError.unavailable
                    }
                    let requestID = random.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
                    struct ChallengeRequest: Encodable { let event: RiskEvent; let timestamp: Int64; let request_id: String }
                    struct RiskChallenge: Decodable { let challenge: String; let ttl_seconds: Int }
                    let challenge: RiskChallenge = try await Self.riskPost(scope.endpoint, "challenge",
                        ChallengeRequest(event: item.event, timestamp: now, request_id: requestID))
                    guard challenge.ttl_seconds == 60,
                          challenge.challenge.range(of: #"\A[A-Za-z0-9_-]{43}\z"#, options: .regularExpression) != nil else {
                        throw ShellsmithResourceError.invalidResponse
                    }
                    let digest = RiskEvent.reportDigest(try item.event.digest(endpoint: scope.endpoint), challenge: challenge.challenge)
                    let proof = try await ShellsmithAppAttest.generateAssertion(scope.keyID, clientDataHash: digest)
                    report = RiskReport(event: item.event, challenge: challenge.challenge, proof: proof.base64EncodedString())
                    guard let position = riskScopes[binding]?.queue.firstIndex(where: { $0.event.event_id == id }) else { continue }
                    riskScopes[binding]?.queue[position].report = report
                    riskScopes[binding]?.queue[position].challengeAt = now
                    guard persistRisk(binding) else { throw ShellsmithResourceError.unavailable }
                }
                struct Receipt: Decodable {
                    let status: String; let event_id: String; let action: String; let authorization_version: Int
                    let current_authorization_version: Int?; let current_status: String?
                }
                let receipt: Receipt = try await Self.riskPost(scope.endpoint, "report", report!)
                guard receipt.status == "accepted", receipt.event_id == id,
                      ["record", "revoke"].contains(receipt.action), receipt.authorization_version >= 0 else {
                    throw ShellsmithResourceError.invalidResponse
                }
                var revoke = false
                if item.event.protocol == 2 {
                    guard let currentVersion = receipt.current_authorization_version,
                          currentVersion >= receipt.authorization_version,
                          let currentStatus = receipt.current_status, ["approved", "revoked"].contains(currentStatus) else {
                        throw ShellsmithResourceError.invalidResponse
                    }
                    if let active = riskScopes[binding], active.keyID == scope.keyID,
                       currentVersion >= (active.authorizationVersion ?? -1) {
                        riskScopes[binding]?.authorizationVersion = currentVersion
                        revoke = currentStatus == "revoked"
                    }
                }
                riskScopes[binding]?.queue.removeAll { $0.event.event_id == id }
                riskScopes[binding]?.failures = 0
                riskScopes[binding]?.next = now + 10
                if revoke {
                    cached.removeAll()
                    ShellsmithRuntime.revokeProtectedAccess()
                    NSLog("R_REVOKED")
                }
            } catch {
                if let invalid = error as? DCError, invalid.code == .invalidKey {
                    invalidateRisk(scope.keyID); NSLog("R_KEY_RESET"); continue
                }
                let status = (error as? RiskHTTPError)?.status
                if let position = riskScopes[binding]?.queue.firstIndex(where: { $0.event.event_id == id }) {
                    let started = riskScopes[binding]?.queue[position].challengeAt ?? now
                    if status == 403, now - started >= 60 {
                        riskScopes[binding]?.queue[position].report = nil
                        riskScopes[binding]?.queue[position].challengeAt = nil
                    } else if status == 400 || status == 409 || error is DecodingError
                                || (error as? ShellsmithResourceError) == .invalidResponse {
                        riskScopes[binding]?.queue[position].stopped = true
                    }
                }
                let failures = min((riskScopes[binding]?.failures ?? 0) + 1, 8)
                riskScopes[binding]?.failures = failures
                let delay = status == 404 ? 3600 : min(3600, 10 << failures)
                riskScopes[binding]?.next = now + Int64(delay + Int.random(in: 0...9))
                NSLog(status == 404 ? "R_CONFIG" : status == 403 ? "R_DENIED" : "R_RETRY")
            }
            _ = persistRisk(binding)
        }
        if riskScopes.values.contains(where: { !$0.queue.isEmpty }) { scheduleRisk(after: 10) }
    }

    private struct RiskHTTPError: Error { let status: Int }

    private static func riskPost<B: Encodable, R: Decodable>(_ endpoint: String, _ operation: String, _ body: B) async throws -> R {
        guard let url = URL(string: endpoint + "/v1/risk-events/" + operation), url.scheme == "https",
              url.host != nil, url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else {
            throw ShellsmithResourceError.invalidResponse
        }
        var request = URLRequest(url: url); request.httpMethod = "POST"; request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let bodyData = try JSONEncoder().encode(body)
        guard bodyData.count <= (operation == "challenge" ? 4096 : 32768) else { throw ShellsmithResourceError.invalidResponse }
        request.httpBody = bodyData
        let session = URLSession(configuration: .ephemeral, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let data: Data = try await withCheckedThrowingContinuation { continuation in
            session.dataTask(with: request) { data, response, error in
                if let error { continuation.resume(throwing: error); return }
                let status = (response as? HTTPURLResponse)?.statusCode ?? 0
                guard status == 200 else { continuation.resume(throwing: RiskHTTPError(status: status)); return }
                guard let data, data.count <= 4096 else { continuation.resume(throwing: ShellsmithResourceError.invalidResponse); return }
                continuation.resume(returning: data)
            }.resume()
        }
        return try JSONDecoder().decode(R.self, from: data)
    }

    func obtain(index: ResourceIndex, token: String, group: String) async throws -> (ResourceLease, String) {
        try Task.checkCancellation()
        guard ShellsmithRuntime.resourceSignal() != "authorization_revoked" else { throw ShellsmithResourceError.denied }
        if let lease = cached[token], lease.until > ProtectedResourceClock.now { return (lease, "cached") }
        cached[token] = nil
        if let existing = pending[token] {
            let lease = try await existing.value
            guard ShellsmithRuntime.resourceSignal() != "authorization_revoked" else { throw ShellsmithResourceError.denied }
            return (lease, "coalesced")
        }
        // 同一设备的所有断言按生成顺序提交，防止跨组并发把旧计数送到服务端。
        let preceding = previous
        let traceId = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let task = Task {
            await preceding?.value
            do { return try await self.request(index: index, token: token, group: group, traceId: traceId) }
            catch { throw ResourceAuthorizationFailure(cause: error, traceId: traceId) }
        }
        previous = Task { _ = try? await task.value }
        pending[token] = task
        defer { pending[token] = nil }
        let lease = try await task.value
        guard ShellsmithRuntime.resourceSignal() != "authorization_revoked" else { throw ShellsmithResourceError.denied }
        cached[token] = lease
        let delay = max(0, lease.until - ProtectedResourceClock.now)
        Task {
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            if cached[token]?.until == lease.until { cached[token] = nil }
        }
        return (lease, "granted")
    }

    private func request(index: ResourceIndex, token: String, group: String, traceId: String) async throws -> ResourceLease {
        guard ShellsmithAppAttest.isSupported else { throw ShellsmithResourceError.unavailable }
        let keyID = try await ShellsmithAppAttest.resourceKeyId(appId: index.app_id, environment: index.environment)
        guard let keyIDBytes = Data(base64Encoded: keyID), keyIDBytes.count == 32 else { throw ShellsmithResourceError.invalidResponse }
        let keyField = keyIDBytes.base64EncodedString()
        activateRisk(index: index, token: token, group: group, keyID: keyID, granted: false)
        guard let privateKey = SecKeyCreateRandomKey([
            kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048
        ] as CFDictionary, nil), let publicKey = SecKeyCopyPublicKey(privateKey),
        let rsa = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            throw ShellsmithResourceError.unavailable
        }
        // Security 返回 PKCS#1；BYOS 统一使用带 rsaEncryption 标识的 SPKI 结构。
        let algorithm = Data([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00])
        let responseKey = Self.der(0x30, algorithm + Self.der(0x03, Data([0]) + rsa)).base64EncodedString()
        var body = ["token_id": token, "build_id": index.build_id, "resource_group": group,
                    "key_id": keyField, "response_public_key": responseKey]
        let started = ProtectedResourceClock.now
        let challengeResponse: Challenge = try await Self.post(index.server_url, "challenge", body, traceId)
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
            invalidateRisk(keyID)
            try ShellsmithAppAttest.forgetResourceKey(appId: index.app_id, environment: index.environment)
            throw ShellsmithResourceError.unavailable
        }
        body["action"] = action
        body["challenge"] = challenge
        body["proof"] = proof.base64EncodedString()
        let response: LeaseResponse = try await Self.post(index.server_url, "fetch", body, traceId)
        if response.status == "pending" { throw ShellsmithResourceError.pendingApproval }
        guard action == "assert", response.status == "granted", let ttl = response.ttl_seconds,
              (1...60).contains(ttl), let envelope = response.wrapped_ikm,
              let wrapped = Data(base64Encoded: envelope), wrapped.count == 256,
              let decrypted = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA256, wrapped as CFData, nil) as Data?,
              decrypted.count == 64, decrypted.prefix(32) == digest else {
            throw ShellsmithResourceError.invalidResponse
        }
        let expires = started + Double(ttl)
        guard expires > ProtectedResourceClock.now else { throw ShellsmithResourceError.denied }
        guard ShellsmithRuntime.resourceSignal() != "authorization_revoked" else { throw ShellsmithResourceError.denied }
        if let capability = response.risk_events_v2 {
            guard capability.authorization_version >= 0 else { throw ShellsmithResourceError.invalidResponse }
            let binding = RiskScope(endpoint: index.server_url, token: token, build: index.build_id, group: group,
                                    keyID: keyID, installation: RiskEvent.hex(keyIDBytes)).binding
            guard capability.authorization_version >= (riskScopes[binding]?.authorizationVersion ?? -1) else {
                throw ShellsmithResourceError.invalidResponse
            }
        }
        activateRisk(index: index, token: token, group: group, keyID: keyID, granted: true,
                     protocolVersion: response.risk_events_v2 == nil ? 1 : 2,
                     authorizationVersion: response.risk_events_v2?.authorization_version)
        return ResourceLease(key: Data(decrypted.suffix(32)), until: expires, traceId: traceId)
    }

    private struct Challenge: Decodable { let action: String; let challenge: String }
    private struct RiskCapability: Decodable { let authorization_version: Int }
    private struct LeaseResponse: Decodable {
        let status: String; let wrapped_ikm: String?; let ttl_seconds: Int?
        let risk_events_v2: RiskCapability?
    }

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
