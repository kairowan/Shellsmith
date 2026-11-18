import CryptoKit
import Foundation

enum ProtectedResourceReadError: Error {
    case invalidContext
    case invalidFormat
    case expired
    case authentication
}

@available(iOS 14.0, macOS 11.0, *)
enum ProtectedResourceReader {
    private static let chunkSize = 64 * 1024
    private static let maximumLength = 16 * 1024 * 1024

    static func read(
        from file: FileHandle,
        build: Data,
        group: String,
        resource: String,
        version: UInt32,
        key: Data,
        authorized: () -> Bool,
        consume: (Data) throws -> Void
    ) throws {
        guard build.count == 16, key.count == 32, version > 0,
              validIdentifier(group), validIdentifier(resource) else {
            throw ProtectedResourceReadError.invalidContext
        }
        var header = try exactly(20, from: file)
        guard header.prefix(4) == Data("SSR1".utf8), header.dropFirst(4) == build else {
            throw ProtectedResourceReadError.invalidContext
        }
        for expected in [group, resource] {
            let length = try exactly(1, from: file)
            guard let size = length.first, (1...64).contains(size) else {
                throw ProtectedResourceReadError.invalidFormat
            }
            let actual = try exactly(Int(size), from: file)
            guard actual == Data(expected.utf8) else { throw ProtectedResourceReadError.invalidContext }
            header.append(length)
            header.append(actual)
        }
        let dimensions = try exactly(12, from: file)
        header.append(dimensions)
        let actualVersion = dimensions.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        let length = dimensions.dropFirst(4).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        guard version == actualVersion, length > 0, length <= maximumLength else {
            throw ProtectedResourceReadError.invalidFormat
        }
        let cipherKey = SymmetricKey(data: key)
        var remaining = Int(length)
        var index: UInt32 = 0
        while remaining > 0 {
            guard authorized() else { throw ProtectedResourceReadError.expired }
            let count = min(Self.chunkSize, remaining)
            let nonce = try exactly(12, from: file)
            let encrypted = try exactly(count, from: file)
            let tag = try exactly(16, from: file)
            if remaining == count, let extra = try file.read(upToCount: 1), !extra.isEmpty {
                throw ProtectedResourceReadError.invalidFormat
            }
            var aad = header
            withUnsafeBytes(of: index.bigEndian) { aad.append(contentsOf: $0) }
            let plaintext: Data
            do {
                let sealed = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: encrypted, tag: tag)
                plaintext = try AES.GCM.open(sealed, using: cipherKey, authenticating: aad)
            } catch {
                throw ProtectedResourceReadError.authentication
            }
            guard authorized() else { throw ProtectedResourceReadError.expired }
            try consume(plaintext)
            remaining -= count
            index += 1
        }
    }

    private static func exactly(_ count: Int, from file: FileHandle) throws -> Data {
        var result = Data()
        while result.count < count {
            guard let next = try file.read(upToCount: count - result.count), !next.isEmpty else {
                throw ProtectedResourceReadError.invalidFormat
            }
            result.append(next)
        }
        return result
    }

    private static func validIdentifier(_ value: String) -> Bool {
        (1...64).contains(value.utf8.count) && value.utf8.allSatisfy { byte in
            (97...122).contains(byte) || (48...57).contains(byte) || byte == 45 || byte == 95
        }
    }
}
