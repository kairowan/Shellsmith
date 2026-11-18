import Foundation

let root = URL(fileURLWithPath: CommandLine.arguments[1])
let id = Array(try String(contentsOf: root.appendingPathComponent("build-id"), encoding: .utf8))
let build = Data(stride(from: 0, to: id.count, by: 2).map { UInt8(String(id[$0...($0 + 1)]), radix: 16)! })
let key = try Data(contentsOf: root.appendingPathComponent("fixture-key"))
let expected = try Data(contentsOf: root.appendingPathComponent("rules.json"))

func read(_ name: String, range: Range<Int>? = nil, active: () -> Bool, consume: (Data) throws -> Void) throws {
    let file = try FileHandle(forReadingFrom: root.appendingPathComponent(name))
    defer { try? file.close() }
    try ProtectedResourceReader.read(from: file, build: build, group: "policy",
        resource: "rules", version: 3, key: key, range: range, authorized: active, consume: consume)
}

var plaintext = Data()
try read("sealed/rules.ssr", active: { true }) { plaintext.append($0) }
precondition(plaintext == expected)
var range = Data()
try read("sealed/rules.ssr", range: 65_530..<65_547, active: { true }) { range.append($0) }
precondition(range == expected.subdata(in: 65_530..<65_547))
for invalid in ["extended", "truncated", "tampered"] {
    var consumed = 0
    do {
        try read(invalid, active: { true }) { consumed += $0.count }
        preconditionFailure("无效末片仍可读取")
    } catch {
        precondition(consumed == 65_536)
    }
    do {
        try read(invalid, range: 0..<1, active: { true }) { _ in }
        preconditionFailure("选择部分字节仍应认证末片")
    } catch {}
}
var valid = true
var consumed = 0
do {
    try read("sealed/rules.ssr", active: { valid }) { data in
        consumed += data.count
        valid = false
    }
    preconditionFailure("授权失效后仍可继续读取")
} catch ProtectedResourceReadError.expired {
    precondition(consumed == 65_536)
}

let grant = ShellsmithSharedResources.Grant(
    key: key, build: SharedResourceSettings.build, issued: 100, until: 160, boot: 1_000, snapshot: UUID())
precondition(grant.active(at: 150, wall: 1_150))
precondition(!grant.active(at: 160, wall: 1_160))
precondition(!grant.active(at: 90, wall: 1_090))
precondition(!grant.active(at: 150, wall: 1_160))
var legacy = try JSONSerialization.jsonObject(with: JSONEncoder().encode(grant)) as! [String: Any]
legacy.removeValue(forKey: "snapshot")
let legacyGrant = try JSONDecoder().decode(
    ShellsmithSharedResources.Grant.self, from: JSONSerialization.data(withJSONObject: legacy))
precondition(legacyGrant.snapshot == nil && legacyGrant.active(at: 150, wall: 1_150))

let oldSnapshot = root.appendingPathComponent("previous.ssg")
let candidate = root.appendingPathComponent("candidate.ssg")
try Data([0xA1]).write(to: oldSnapshot)
do {
    try ShellsmithSharedResources.writeSnapshot(Data([0xB2]), to: candidate) {
        precondition(FileManager.default.fileExists(atPath: candidate.path))
        throw CocoaError(.fileWriteNoPermission)
    }
    preconditionFailure("Keychain 写入失败不应提交新快照")
} catch let error as CocoaError where error.code == .fileWriteNoPermission {
    precondition(!FileManager.default.fileExists(atPath: candidate.path))
    let previous = try Data(contentsOf: oldSnapshot)
    precondition(previous == Data([0xA1]))
}
