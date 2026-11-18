import CryptoKit
import Foundation
import Security

/// 独立于 DeviceCheck 的 App Extension 读取入口。主应用负责取钥与发布。
@available(iOS 14.0, *)
public enum ShellsmithSharedResources {
    public enum Failure: Error { case invalidResource, unavailable, expired, invalidSnapshot }

    private struct Grant: Codable {
        let key: Data
        let build: String
        let issued: TimeInterval
        let until: TimeInterval
        let boot: TimeInterval

        var active: Bool {
            let uptime = ProcessInfo.processInfo.systemUptime
            let estimatedBoot = Date().timeIntervalSince1970 - uptime
            return build == SharedResourceSettings.build && key.count == 32
                && until - issued <= 60 && issued <= uptime && uptime < until
                && abs(estimatedBoot - boot) <= 2
        }
    }

    private static let writer = NSLock()
    private static let limit = 16 * 1024 * 1024

    public static func data(_ id: String) throws -> Data {
        let (url, query, aad) = try location(id)
        var attributes = query
        attributes[kSecReturnData as String] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(attributes as CFDictionary, &result) == errSecSuccess,
              let encoded = result as? Data else { throw Failure.unavailable }
        let grant = try JSONDecoder().decode(Grant.self, from: encoded)
        guard grant.active else { throw Failure.expired }
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        guard let ciphertext = try file.read(upToCount: limit + 29), ciphertext.count <= limit + 28 else {
            throw Failure.invalidSnapshot
        }
        let sealed = try AES.GCM.SealedBox(combined: ciphertext)
        let data = try AES.GCM.open(sealed, using: SymmetricKey(data: grant.key), authenticating: aad)
        guard grant.active else { throw Failure.expired }
        return data
    }

    static func publish(_ data: Data, id: String, until: TimeInterval) throws {
        guard (1...limit).contains(data.count) else { throw Failure.invalidResource }
        let (url, query, aad) = try location(id)
        writer.lock()
        defer { writer.unlock() }
        let now = ProcessInfo.processInfo.systemUptime
        guard until > now && until - now <= 60 else { throw Failure.expired }
        let key = SymmetricKey(size: .bits256)
        let grant = Grant(key: key.withUnsafeBytes { Data($0) }, build: SharedResourceSettings.build,
                          issued: now, until: until,
                          boot: Date().timeIntervalSince1970 - now)
        let encrypted = try AES.GCM.seal(data, using: key, authenticating: aad)
        guard let ciphertext = encrypted.combined else { throw Failure.invalidSnapshot }

        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.protectionKey: FileProtectionType.complete])
        var excluded = directory
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try excluded.setResourceValues(resourceValues)
        guard grant.active else { throw Failure.expired }
        try ciphertext.write(to: url, options: [.atomic, .completeFileProtection])
        let value = try JSONEncoder().encode(grant)
        let update = [kSecValueData as String: value]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var create = query
            create[kSecValueData as String] = value
            create[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            guard SecItemAdd(create as CFDictionary, nil) == errSecSuccess else { throw Failure.unavailable }
        } else if status != errSecSuccess {
            throw Failure.unavailable
        }
    }

    static func invalidate(_ id: String) throws {
        let (url, query, _) = try location(id)
        writer.lock()
        defer { writer.unlock() }
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw Failure.unavailable }
        do { try FileManager.default.removeItem(at: url) }
        catch let error as CocoaError where error.code == .fileNoSuchFile {}
    }

    private static func location(_ id: String) throws -> (URL, [String: Any], Data) {
        guard id.range(of: #"\A[a-z0-9_-]{1,64}\z"#, options: .regularExpression) != nil else {
            throw Failure.invalidResource
        }
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: SharedResourceSettings.group
        ) else { throw Failure.unavailable }
        let directory = container.appendingPathComponent("ShellsmithResources", isDirectory: true)
            .appendingPathComponent(SharedResourceSettings.host, isDirectory: true)
        let context = ["shellsmith-shared-resource-v1", SharedResourceSettings.group,
                       SharedResourceSettings.build, id].joined(separator: "\n")
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "dev.shellsmith.resources.shared",
            kSecAttrAccount as String: SharedResourceSettings.host + ":" + id,
            kSecAttrAccessGroup as String: SharedResourceSettings.keychain,
            kSecAttrSynchronizable as String: false,
        ]
        return (directory.appendingPathComponent(id + ".ssg"), query, Data(context.utf8))
    }
}
