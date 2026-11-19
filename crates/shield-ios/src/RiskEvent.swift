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

    func digest(endpoint: String) -> Data {
        Self.hash(["shellsmith-risk-event-v1", endpoint, String(`protocol`), platform, token_id,
                   build_id, resource_group, installation_id, event_id, String(detected_at),
                   detection_code, detector_version].joined(separator: "\n"))
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

    var binding: String {
        RiskEvent.hex(RiskEvent.hash([endpoint, token, build, group, installation].joined(separator: "\n")))
    }
}
