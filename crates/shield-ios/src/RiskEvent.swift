import CryptoKit
import Foundation

// 规范化消息不依赖 JSON 字段顺序，重试保留事件原文与检测时间。
struct RiskEvent: Codable, Sendable {
    let `protocol`: Int
    let platform: String
    let token_id: String
    let build_id: String
    let resource_group: String
    let installation_id: String
    let event_id: String
    let detected_at: Int64
    let detection_code: String
    let detector_version: String
    var evidence: [String: String]? = nil

    func digest(endpoint: String) throws -> Data {
        guard (`protocol` == 1 && evidence == nil) || (`protocol` == 2 && evidence != nil) else {
            throw ShellsmithResourceError.invalidResponse
        }
        var fields = ["shellsmith-risk-event-v\(`protocol`)", endpoint, String(`protocol`), platform, token_id,
                   build_id, resource_group, installation_id, event_id, String(detected_at),
                   detection_code, detector_version]
        if let evidence { fields.append(Self.hex(try Self.evidenceDigest(evidence))) }
        return Self.hash(fields.joined(separator: "\n"))
    }
    static func evidenceDigest(_ evidence: [String: String]) throws -> Data {
        guard (1...32).contains(evidence.count), evidence["schema"] == "1" else {
            throw ShellsmithResourceError.invalidResponse
        }
        var fields = ["shellsmith-risk-evidence-v1"]
        for key in evidence.keys.sorted() {
            let value = evidence[key]!
            guard key.range(of: #"\A[a-z][a-z0-9_]{0,47}\z"#, options: .regularExpression) != nil,
                  value.utf8.count <= 256, !value.utf8.contains(where: { $0 < 32 || $0 == 127 }) else {
                throw ShellsmithResourceError.invalidResponse
            }
            fields.append(key + "=" + value)
        }
        let canonical = fields.joined(separator: "\n")
        guard canonical.utf8.count <= 2048 else { throw ShellsmithResourceError.invalidResponse }
        return hash(canonical)
    }
    static func iosEvidence(_ code: String) -> [String: String] {
        func clean(_ value: String?) -> String {
            guard let value, value.utf8.count <= 128, !value.utf8.contains(where: { $0 < 32 || $0 == 127 }) else { return "unavailable" }
            return value
        }
        var result = ShellsmithRuntime.riskEvidence(for: code)
        result["schema"] = "1"
        result["app_id"] = clean(Bundle.main.bundleIdentifier)
        result["app_version"] = clean(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)
        result["app_version_code"] = clean(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String)
        result["os_version"] = clean(ProcessInfo.processInfo.operatingSystemVersionString)
        result["process_name"] = clean(ProcessInfo.processInfo.processName)
        result["payload"] = "resource_group"
        return result
    }
    static func challengeDigest(_ digest: Data, timestamp: Int64, requestID: String) -> Data {
        hash(["shellsmith-risk-challenge-v1", hex(digest), String(timestamp), requestID].joined(separator: "\n"))
    }
    static func reportDigest(_ digest: Data, challenge: String) -> Data {
        hash(["shellsmith-risk-report-v1", hex(digest), challenge].joined(separator: "\n"))
    }
    static func hash(_ value: String) -> Data { Data(SHA256.hash(data: Data(value.utf8))) }
    static func hex(_ value: Data) -> String { value.map { String(format: "%02x", $0) }.joined() }
}

struct RiskReport: Codable, Sendable {
    let event: RiskEvent
    let challenge: String
    let proof: String
}

struct RiskItem: Codable, Sendable {
    let event: RiskEvent
    var report: RiskReport?
    var challengeAt: Int64?
    var stopped = false
}

struct RiskScope: Codable, Sendable {
    let endpoint: String
    let token: String
    let build: String
    let group: String
    let keyID: String
    let installation: String
    var queue: [RiskItem] = []
    var failures = 0
    var next: Int64 = 0
    var protocolVersion: Int?
    var authorizationVersion: Int?

    var binding: String {
        RiskEvent.hex(RiskEvent.hash([endpoint, token, build, group, installation].joined(separator: "\n")))
    }
}
