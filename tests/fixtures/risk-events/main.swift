import CryptoKit
import DeviceCheck
import Foundation
import Security

struct Vector: Decodable {
    let public_base_url: String; let event: RiskEvent; let timestamp: Int64
    let request_id: String; let challenge: String
    let event_digest: String; let challenge_digest: String; let report_digest: String
}
let vector = try JSONDecoder().decode(Vector.self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
let digest = vector.event.digest(endpoint: vector.public_base_url)
precondition(RiskEvent.hex(digest) == vector.event_digest)
precondition(RiskEvent.hex(RiskEvent.challengeDigest(digest, timestamp: vector.timestamp, requestID: vector.request_id)) == vector.challenge_digest)
precondition(RiskEvent.hex(RiskEvent.reportDigest(digest, challenge: vector.challenge)) == vector.report_digest)

// 软件证明仅检验客户端调度、封装校验和确认流程，不代表 Apple 或 HTTPS 验收。
enum ShellsmithRuntime {
    static func resourceSignal() -> String { "clear" }
    static func riskSignals() -> [String] { [] }
}
extension Bundle { static var module: Bundle { .main } }
enum ShellsmithAppAttest {
    static var isSupported = true
    static var counter = 0
    static let identity = Data(repeating: 3, count: 32).base64EncodedString()
    static func resourceKeyId(appId: String, environment: String) async throws -> String { identity }
    static func forgetResourceKey(appId: String, environment: String) throws {}
    static func attestKey(_ id: String, clientDataHash: Data) async throws -> Data { Data() }
    static func generateAssertion(_ id: String, clientDataHash: Data) async throws -> Data {
        counter += 1
        let result = Data(String(counter).utf8)
        try await Task.sleep(nanoseconds: 20_000_000)
        return result
    }
}
enum RiskHarness {
    static var mode = "denied"
    static var counters: [Int] = []
    static var reports = 0
    static var stored: RiskReport?
    static var lost = true
    static func sessionConfiguration() -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [HarnessProtocol.self]; return config
    }
    static func response(_ request: URLRequest, _ bytes: Data) throws -> (Int, Data) {
        precondition(request.value(forHTTPHeaderField: "Authorization") == nil)
        precondition(request.value(forHTTPHeaderField: "Cookie") == nil)
        let body = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        let route = request.url!.path
        var result: [String: Any]
        if route == "/prefix/v1/ios-resource-keys/challenge" {
            result = ["action": "assert", "challenge": String(repeating: "A", count: 96)]
        } else if route == "/prefix/v1/ios-resource-keys/fetch" {
            counters.append(Int(String(data: Data(base64Encoded: body["proof"] as! String)!, encoding: .utf8)!)!)
            if mode == "denied" { return (403, Data()) }
            let fields = ["shellsmith-ios-resource-v1", "TEAM.com.example.app", "development", "assert",
                body["token_id"] as! String, body["build_id"] as! String, body["resource_group"] as! String,
                body["key_id"] as! String, body["response_public_key"] as! String, body["challenge"] as! String]
            var plain = Data(SHA256.hash(data: Data(fields.joined(separator: "\n").utf8))) + Data(repeating: 42, count: 32)
            if mode == "digest" { plain[0] ^= 1 }
            let spki = Data(base64Encoded: body["response_public_key"] as! String)!
            let key = SecKeyCreateWithData(Data(spki.dropFirst(24)) as CFData,
                [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary, nil)!
            let wrapped = SecKeyCreateEncryptedData(key, .rsaEncryptionOAEPSHA256, plain as CFData, nil)! as Data
            result = ["status": "granted", "ttl_seconds": 60, "wrapped_ikm": wrapped.base64EncodedString()]
        } else if route == "/prefix/v1/risk-events/challenge" {
            precondition(body["signature"] == nil)
            result = ["challenge": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "ttl_seconds": 60]
        } else {
            precondition(route == "/prefix/v1/risk-events/report")
            let report = try JSONDecoder().decode(RiskReport.self, from: bytes)
            reports += 1
            if let stored {
                precondition(stored.proof == report.proof && stored.challenge == report.challenge
                    && stored.event.digest(endpoint: "https://test.invalid/prefix") == report.event.digest(endpoint: "https://test.invalid/prefix"))
            }
            else {
                stored = report
                counters.append(Int(String(data: Data(base64Encoded: report.proof)!, encoding: .utf8)!)!)
            }
            if lost { lost = false; return (503, Data()) }
            result = ["status": "accepted", "event_id": report.event.event_id, "action": "revoke", "authorization_version": 3]
        }
        return (200, try JSONSerialization.data(withJSONObject: result))
    }
}
final class HarnessProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}
    override func startLoading() {
        do {
            var bytes = request.httpBody ?? Data()
            if let stream = request.httpBodyStream {
                stream.open(); defer { stream.close() }
                var buffer = [UInt8](repeating: 0, count: 1024)
                while true { let count = stream.read(&buffer, maxLength: buffer.count); if count <= 0 { break }; bytes.append(contentsOf: buffer.prefix(count)) }
            }
            let (status, data) = try RiskHarness.response(request, bytes)
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data); client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
}

let semaphore = DispatchSemaphore(value: 0)
Task {
    let actor = ResourceAuthorization()
    let directory = ResourceAuthorization.riskDirectory
    // 检查脚本把存储目录改到隔离临时目录。
    defer { try? FileManager.default.removeItem(at: directory); semaphore.signal() }
    let build = String(repeating: "a", count: 32)
    let token = "r_" + String(repeating: "b", count: 64)
    let index = ResourceIndex(version: 1, build_id: build, app_id: "TEAM.com.example.app", environment: "development",
        server_url: "https://test.invalid/prefix", groups: ["policy": token], resources: [:], key_source: "byos", risk_protocol: 1)
    do {
        let local = ResourceIndex(version: 1, build_id: build, app_id: index.app_id, environment: index.environment,
            server_url: index.server_url, groups: index.groups, resources: [:], key_source: "local", risk_protocol: 1)
        await actor.activateRisk(index: local, token: token, group: "policy", keyID: ShellsmithAppAttest.identity, granted: true)
        let localObserver = await actor.riskObserver
        precondition(localObserver == nil && !FileManager.default.fileExists(atPath: directory.path))
        let legacy = ResourceIndex(version: 1, build_id: build, app_id: index.app_id, environment: index.environment,
            server_url: index.server_url, groups: index.groups, resources: [:], key_source: nil, risk_protocol: nil)
        await actor.activateRisk(index: legacy, token: token, group: "policy", keyID: ShellsmithAppAttest.identity, granted: true)
        let legacyObserver = await actor.riskObserver
        precondition(legacyObserver == nil && !FileManager.default.fileExists(atPath: directory.path))
        for mode in ["denied", "digest"] {
            RiskHarness.mode = mode
            do { _ = try await actor.obtain(index: index, token: token, group: "policy"); preconditionFailure("无效取钥被放行") } catch {}
            let observer = await actor.riskObserver
            precondition(observer == nil && !FileManager.default.fileExists(atPath: directory.path))
        }
        RiskHarness.mode = "granted"
        let lease = try await actor.obtain(index: index, token: token, group: "policy").0
        precondition(lease.key == Data(repeating: 42, count: 32))
        let observer = await actor.riskObserver
        precondition(observer != nil)
        try FileManager.default.removeItem(at: directory)
        try Data([0]).write(to: directory)
        await actor.detectedRisk("debugger", at: Int64(Date().timeIntervalSince1970))
        await actor.flushRisk()
        precondition(RiskHarness.reports == 0)
        try FileManager.default.removeItem(at: directory)
        await actor.flushRisk()
        precondition(RiskHarness.reports == 1)
        let scopes = await actor.riskScopes
        precondition(scopes.values.first!.queue.first!.report != nil)
        let newToken = "r_" + String(repeating: "c", count: 64)
        let expanded = ResourceIndex(version: 1, build_id: build, app_id: index.app_id, environment: index.environment,
            server_url: index.server_url, groups: ["policy": token, "media": newToken], resources: [:], key_source: "byos", risk_protocol: 1)
        let next = Task { try await actor.obtain(index: expanded, token: newToken, group: "media") }
        await actor.queueRisk()
        _ = try await next.value
        // 等待共用尾任务，随后强制到期重发原报告。
        await actor.previous?.value
        await actor.forceRiskRetry()
        precondition(RiskHarness.reports == 2)
        precondition(RiskHarness.counters == RiskHarness.counters.sorted())
        precondition(Set(RiskHarness.counters).count == RiskHarness.counters.count)
        let queues = await actor.riskScopes
        precondition(queues.values.allSatisfy { $0.queue.isEmpty })
        // 重启恢复不需要再次获取 IKM，标记本身不改变资源租约。
        let restored = ResourceAuthorization()
        await restored.activateRisk(index: expanded, token: token, group: "policy", keyID: ShellsmithAppAttest.identity, granted: false)
        let restoredObserver = await restored.riskObserver
        precondition(restoredObserver != nil)
        let freshKey = Data(repeating: 4, count: 32).base64EncodedString()
        await restored.activateRisk(index: expanded, token: token, group: "policy", keyID: freshKey, granted: false)
        let freshObserver = await restored.riskObserver
        precondition(freshObserver == nil)
        print("Swift 固定向量、取钥拒绝、OAEP 摘要校验、成功启用、原报告重试与共享计数串行通过")
    } catch { fatalError("回归失败：\(error)") }
}
while semaphore.wait(timeout: .now()) == .timedOut { RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.01)) }
