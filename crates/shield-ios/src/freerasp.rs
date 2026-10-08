use crate::{
    ShellsmithIosConfig, FREERASP_IOS_VERSION, SWIFT_CONFIDENTIAL_PLUGIN_VERSION,
    SWIFT_CONFIDENTIAL_VERSION,
};

pub(crate) const KNOWN_THREATS: &[&str] = &[
    "signature",
    "jailbreak",
    "debugger",
    "runtimeManipulation",
    "passcode",
    "passcodeChange",
    "simulator",
    "missingSecureEnclave",
    "systemVPN",
    "deviceChange",
    "deviceID",
    "unofficialStore",
    "screenshot",
    "screenRecording",
    "timeSpoofing",
];

pub(crate) fn package_manifest(confidential: bool, rasp: bool) -> String {
    let mut dependencies = Vec::new();
    let mut target_dependencies = Vec::new();
    let mut plugins = Vec::new();
    let mut exclude = Vec::new();
    if confidential {
        dependencies.push(format!(
            ".package(url: \"https://github.com/securevale/swift-confidential.git\", exact: \"{SWIFT_CONFIDENTIAL_VERSION}\")"
        ));
        dependencies.push(format!(
            ".package(url: \"https://github.com/securevale/swift-confidential-plugin.git\", exact: \"{SWIFT_CONFIDENTIAL_PLUGIN_VERSION}\")"
        ));
        target_dependencies.push(
            ".product(name: \"ConfidentialKit\", package: \"swift-confidential\")".to_string(),
        );
        plugins.push(
            ".plugin(name: \"Confidential\", package: \"swift-confidential-plugin\")".to_string(),
        );
        exclude.push("\"confidential.yml\"".to_string());
    }
    if rasp {
        dependencies.push(format!(
            ".package(url: \"https://github.com/talsec/Free-RASP-iOS.git\", exact: \"{FREERASP_IOS_VERSION}\")"
        ));
        target_dependencies
            .push(".product(name: \"TalsecRuntime\", package: \"Free-RASP-iOS\")".to_string());
    }
    format!(
        "// swift-tools-version: 6.0\n\
         import PackageDescription\n\n\
         let package = Package(\n\
             name: \"ShellsmithRuntime\",\n\
             platforms: [.iOS(.v13)],\n\
             products: [.library(name: \"ShellsmithRuntime\", targets: [\"ShellsmithRuntime\"])],\n\
             dependencies: [\n{dependencies}\n             ],\n\
             targets: [\n\
                 .target(\n\
                     name: \"ShellsmithRuntime\",\n\
                     dependencies: [\n{target_dependencies}\n                     ],\n\
                     exclude: [{exclude}],\n\
                     plugins: [{plugins}]\n\
                 )\n\
             ],\n\
             swiftLanguageModes: [.v5]\n\
         )\n",
        dependencies = indent_items(&dependencies, 8),
        target_dependencies = indent_items(&target_dependencies, 24),
        exclude = exclude.join(", "),
        plugins = plugins.join(", "),
    )
}

pub(crate) fn runtime_source(rasp: bool) -> String {
    if !rasp {
        return "import Foundation\n\npublic enum ShellsmithRuntime {}\n".to_string();
    }
    r#"import Dispatch
import Foundation
import TalsecRuntime

public enum ShellsmithThreatSeverity: String, Sendable {
    case observe
    case restrict
    case critical
}

public struct ShellsmithThreatEvent: Sendable {
    public let name: String
    public let severity: ShellsmithThreatSeverity
}

public extension Notification.Name {
    static let shellsmithThreatDetected = Notification.Name("dev.shellsmith.threat-detected")
}

public enum ShellsmithRuntime {
    private enum State {
        case idle
        case starting
        case started
    }

    private static let lock = NSLock()
    private static var state: State = .idle
    private static var criticalThreats = Set<String>()
    private static var handler: ((ShellsmithThreatEvent) -> Void)?
    private static var events: [String: ShellsmithThreatEvent] = [:]

    public static func start(
        bundleIds: [String],
        teamId: String,
        watcherMail: String?,
        isProd: Bool,
        critical: [String],
        onThreat: ((ShellsmithThreatEvent) -> Void)? = nil
    ) {
        var shouldStart = false
        var replay: [ShellsmithThreatEvent] = []
        lock.lock()
        switch state {
        case .idle:
            state = .starting
            criticalThreats = Set(critical)
            handler = onThreat
            shouldStart = true
        case .starting, .started:
            if let onThreat {
                handler = onThreat
                replay = events.values.sorted { $0.name < $1.name }
            }
        }
        lock.unlock()

        // Do not call third-party startup while holding our lock. Some RASP
        // implementations can report a finding synchronously during startup.
        if shouldStart {
            Talsec.start(config: TalsecConfig(
                appBundleIds: bundleIds,
                appTeamId: teamId,
                watcherMailAddress: watcherMail,
                isProd: isProd
            ))
            lock.lock()
            state = .started
            lock.unlock()
        }
        for event in replay {
            deliver(event, to: onThreat)
        }
    }

    public static func hasDetected(_ threat: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return events[threat] != nil
    }

    public static func observedThreats() -> [ShellsmithThreatEvent] {
        lock.lock()
        defer { lock.unlock() }
        return events.values.sorted { $0.name < $1.name }
    }

    public static func shouldRestrictSensitiveOperations() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return events.values.contains { event in
            event.severity == .restrict || event.severity == .critical
        }
    }

    static func receive(_ threat: SecurityThreat) {
        let name = stableName(threat)
        lock.lock()
        let severity: ShellsmithThreatSeverity
        if criticalThreats.contains(name) {
            severity = .critical
        } else if [.signature, .jailbreak, .debugger, .runtimeManipulation].contains(threat) {
            severity = .restrict
        } else {
            severity = .observe
        }
        let event = ShellsmithThreatEvent(name: name, severity: severity)
        let isNew = events.updateValue(event, forKey: name) == nil
        let callback = handler
        lock.unlock()
        guard isNew else { return }
        deliver(event, to: callback)
    }

    private static func deliver(
        _ event: ShellsmithThreatEvent,
        to callback: ((ShellsmithThreatEvent) -> Void)?
    ) {
        DispatchQueue.main.async {
            callback?(event)
            NotificationCenter.default.post(
                name: .shellsmithThreatDetected,
                object: nil,
                userInfo: ["threat": event.name, "severity": event.severity.rawValue]
            )
        }
    }

    private static func stableName(_ threat: SecurityThreat) -> String {
        switch threat {
        case .signature: return "signature"
        case .jailbreak: return "jailbreak"
        case .debugger: return "debugger"
        case .runtimeManipulation: return "runtimeManipulation"
        case .passcode: return "passcode"
        case .passcodeChange: return "passcodeChange"
        case .simulator: return "simulator"
        case .missingSecureEnclave: return "missingSecureEnclave"
        case .systemVPN: return "systemVPN"
        case .deviceChange: return "deviceChange"
        case .deviceID: return "deviceID"
        case .unofficialStore: return "unofficialStore"
        case .screenshot: return "screenshot"
        case .screenRecording: return "screenRecording"
        case .timeSpoofing: return "timeSpoofing"
        }
    }
}

extension SecurityThreatCenter: SecurityThreatHandler {
    public func threatDetected(_ securityThreat: TalsecRuntime.SecurityThreat) {
        ShellsmithRuntime.receive(securityThreat)
    }
}
"#
    .to_string()
}

pub(crate) fn protection_source(config: &ShellsmithIosConfig) -> String {
    let rasp = config.rasp.as_ref().filter(|item| item.enabled);
    let bundle_ids = config
        .project
        .bundle_ids
        .iter()
        .map(|value| format!("\"{}\"", swift_escape(value)))
        .collect::<Vec<_>>()
        .join(", ");
    let watcher = rasp
        .and_then(|item| item.watcher_mail.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("\"{}\"", swift_escape(value)))
        .unwrap_or_else(|| "nil".to_string());
    let critical = rasp
        .map(|item| {
            item.critical
                .iter()
                .map(|value| format!("\"{}\"", swift_escape(value)))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let endpoint = config
        .protection
        .app_attest_endpoint
        .as_deref()
        .map(|value| format!("\"{}\"", swift_escape(value)))
        .unwrap_or_else(|| "nil".to_string());
    let start_body = if config.protection.profile.uses_rasp() {
        format!(
            "ShellsmithRuntime.start(\n            bundleIds: [{bundle_ids}],\n            teamId: \"{team}\",\n            watcherMail: {watcher},\n            isProd: {is_prod},\n            critical: [{critical}],\n            onThreat: onThreat\n        )",
            team = swift_escape(&config.project.team_id),
            is_prod = if config.protection.is_prod { "true" } else { "false" },
        )
    } else {
        "_ = onThreat".to_string()
    };
    format!(
        "import Foundation\n\n\
         public enum ShellsmithProtection {{\n\
             public static let profile = \"{}\"\n\
             public static let appAttestEndpoint: String? = {}\n\n\
             public static func start(onThreat: ((ShellsmithThreatEvent) -> Void)? = nil) {{\n\
                 {}\n\
             }}\n\
         }}\n\n\
         @objc(ShellsmithProtectionBootstrap)\n\
         public final class ShellsmithProtectionBootstrap: NSObject {{\n\
             @objc public static func start() {{\n\
                 ShellsmithProtection.start()\n\
             }}\n\
         }}\n",
        config.protection.profile.as_str(),
        endpoint,
        indent_multiline(&start_body, 8),
    )
}

pub(crate) fn app_attest_source(enabled: bool) -> String {
    if !enabled {
        return String::new();
    }
    r#"import CryptoKit
import DeviceCheck
import Foundation
import Security

@available(iOS 14.0, *)
public struct ShellsmithAppAttestEnvelope: Codable, Sendable {
    public let keyId: String
    public let clientDataHash: String
    public let object: String

    public init(keyId: String, clientDataHash: String, object: String) {
        self.keyId = keyId
        self.clientDataHash = clientDataHash
        self.object = object
    }
}

@available(iOS 14.0, *)
public enum ShellsmithAppAttest {
    private static let keychainService = "dev.shellsmith.app-attest-key"
    public static var isSupported: Bool { DCAppAttestService.shared.isSupported }

    public static func keyId() async throws -> String {
        if let stored = try readKeyId() {
            return stored
        }
        let generated = try await generateKey()
        try saveKeyId(generated)
        return try readKeyId() ?? generated
    }

    public static func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.generateKey { keyId, error in
                if let keyId { continuation.resume(returning: keyId) }
                else { continuation.resume(throwing: error ?? ShellsmithAppAttestError.missingResult) }
            }
        }
    }

    public static func makeAttestationEnvelope(challenge: Data) async throws -> ShellsmithAppAttestEnvelope {
        let keyId = try await keyId()
        let digest = clientDataHash(challenge)
        let object = try await attestKey(keyId, clientDataHash: digest)
        return ShellsmithAppAttestEnvelope(
            keyId: keyId,
            clientDataHash: digest.base64EncodedString(),
            object: object.base64EncodedString()
        )
    }

    public static func makeAssertionEnvelope(challenge: Data) async throws -> ShellsmithAppAttestEnvelope {
        let keyId = try await keyId()
        let digest = clientDataHash(challenge)
        let object = try await generateAssertion(keyId, clientDataHash: digest)
        return ShellsmithAppAttestEnvelope(
            keyId: keyId,
            clientDataHash: digest.base64EncodedString(),
            object: object.base64EncodedString()
        )
    }

    public static func submit(
        _ envelope: ShellsmithAppAttestEnvelope,
        to endpoint: String
    ) async throws -> Data {
        guard let url = URL(string: endpoint), url.scheme == "https" else {
            throw ShellsmithAppAttestError.invalidEndpoint
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 10
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(envelope)
        return try await withCheckedThrowingContinuation { continuation in
            URLSession.shared.dataTask(with: request) { data, response, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let http = response as? HTTPURLResponse,
                      (200..<300).contains(http.statusCode),
                      let data else {
                    continuation.resume(throwing: ShellsmithAppAttestError.invalidResponse)
                    return
                }
                continuation.resume(returning: data)
            }.resume()
        }
    }

    public static func clientDataHash(_ challenge: Data) -> Data {
        Data(SHA256.hash(data: challenge))
    }

    public static func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientDataHash) { object, error in
                if let object { continuation.resume(returning: object) }
                else { continuation.resume(throwing: error ?? ShellsmithAppAttestError.missingResult) }
            }
        }
    }

    public static func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
                if let assertion { continuation.resume(returning: assertion) }
                else { continuation.resume(throwing: error ?? ShellsmithAppAttestError.missingResult) }
            }
        }
    }

    private static func readKeyId() throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: Bundle.main.bundleIdentifier ?? "app",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw ShellsmithAppAttestError.keychain(status)
        }
        return String(data: data, encoding: .utf8)
    }

    private static func saveKeyId(_ keyId: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: Bundle.main.bundleIdentifier ?? "app",
            kSecValueData as String: Data(keyId.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw ShellsmithAppAttestError.keychain(status)
        }
    }
}

public enum ShellsmithAppAttestError: Error {
    case missingResult
    case keychain(OSStatus)
    case invalidEndpoint
    case invalidResponse
}
"#
    .to_string()
}

fn indent_items(items: &[String], spaces: usize) -> String {
    let prefix = " ".repeat(spaces);
    items
        .iter()
        .map(|item| format!("{prefix}{item},"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn indent_multiline(value: &str, spaces: usize) -> String {
    let prefix = " ".repeat(spaces);
    value
        .lines()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                line.to_string()
            } else {
                format!("{prefix}{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn swift_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IosProjectConfig, IosProtectionConfig, IosProtectionProfile};
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    #[test]
    fn package_versions_are_exact_and_equal() {
        let manifest = package_manifest(true, true);
        assert!(manifest.contains("exact: \"0.5.2\""));
        assert!(manifest.contains("exact: \"7.1.4\""));
        assert!(manifest.contains(".plugin(name: \"Confidential\""));
    }

    #[test]
    fn generated_package_manifest_is_valid_swiftpm() {
        if Command::new("swift").arg("--version").output().is_err() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Package.swift"),
            package_manifest(true, true),
        )
        .unwrap();
        let output = Command::new("swift")
            .args(["package", "dump-package"])
            .current_dir(temp.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn runtime_handles_every_documented_threat() {
        let source = runtime_source(true);
        for threat in KNOWN_THREATS {
            assert!(source.contains(threat));
        }
        assert!(source.contains("SecurityThreatHandler"));
    }

    #[test]
    fn runtime_events_are_safe_for_lifecycle_consumers() {
        let source = runtime_source(true);
        assert!(source.contains("DispatchQueue.main.async"));
        assert!(source.contains("events.updateValue"));
        assert!(source.contains("observedThreats"));
        assert!(source.contains("shouldRestrictSensitiveOperations"));
        let startup = source.find("Talsec.start").unwrap();
        assert!(source[..startup].rfind("lock.unlock()").is_some());
    }

    #[test]
    fn app_attest_source_keeps_key_and_exposes_server_envelope() {
        let source = app_attest_source(true);
        assert!(source.contains("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"));
        assert!(source.contains("makeAttestationEnvelope"));
        assert!(source.contains("makeAssertionEnvelope"));
        assert!(source.contains("invalidEndpoint"));
    }

    #[test]
    fn generated_swift_sources_are_parseable_when_swift_is_available() {
        if Command::new("swiftc").arg("--version").output().is_err() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("Runtime.swift");
        let attest = temp.path().join("Attest.swift");
        fs::write(&runtime, runtime_source(true)).unwrap();
        fs::write(&attest, app_attest_source(true)).unwrap();
        for path in [runtime, attest] {
            let output = Command::new("swiftc")
                .args(["-parse"])
                .arg(path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn objc_bootstrap_is_exported_by_swift_module_on_macos() {
        if !cfg!(target_os = "macos") || Command::new("swift").arg("--version").output().is_err() {
            return;
        }
        let config = ShellsmithIosConfig {
            project: IosProjectConfig {
                path: PathBuf::from("App.xcodeproj"),
                scheme: "App".into(),
                configuration: "Release".into(),
                team_id: "ABCDE12345".into(),
                bundle_ids: vec!["com.example.app".into()],
                entrypoint: None,
            },
            protection: IosProtectionConfig {
                profile: IosProtectionProfile::Compat,
                ..IosProtectionConfig::default()
            },
            confidential: None,
            rasp: None,
        };
        let temp = tempfile::tempdir().unwrap();
        let package = temp.path().join("Package.swift");
        fs::write(
            &package,
            "// swift-tools-version: 6.0\nimport PackageDescription\nlet package = Package(name: \"BridgeCheck\", platforms: [.macOS(.v11)], products: [.library(name: \"Client\", targets: [\"Client\"])], targets: [.target(name: \"ShellsmithRuntime\"), .target(name: \"Client\", dependencies: [\"ShellsmithRuntime\"])])\n",
        )
        .unwrap();
        let runtime_sources = temp.path().join("Sources/ShellsmithRuntime");
        let client_sources = temp.path().join("Sources/Client");
        fs::create_dir_all(&runtime_sources).unwrap();
        fs::create_dir_all(client_sources.join("include")).unwrap();
        fs::write(
            runtime_sources.join("Bootstrap.swift"),
            format!(
                "public struct ShellsmithThreatEvent {{}}\n{}",
                protection_source(&config)
            ),
        )
        .unwrap();
        fs::write(
            client_sources.join("include/Client.h"),
            "void startProtection(void);\n",
        )
        .unwrap();
        fs::write(
            client_sources.join("Client.m"),
            "@import ShellsmithRuntime;\nvoid startProtection(void) { [ShellsmithProtectionBootstrap start]; }\n",
        )
        .unwrap();
        let output = Command::new("swift")
            .args(["build", "--package-path"])
            .arg(temp.path())
            .arg("--scratch-path")
            .arg(temp.path().join("build"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
