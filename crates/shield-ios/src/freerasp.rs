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
    r#"import Foundation
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
    private static let lock = NSLock()
    private static var started = false
    private static var criticalThreats = Set<String>()
    private static var handler: ((ShellsmithThreatEvent) -> Void)?
    private static var detected = Set<String>()

    public static func start(
        bundleIds: [String],
        teamId: String,
        watcherMail: String?,
        isProd: Bool,
        critical: [String],
        onThreat: ((ShellsmithThreatEvent) -> Void)? = nil
    ) {
        lock.lock()
        defer { lock.unlock() }
        guard !started else { return }
        criticalThreats = Set(critical)
        handler = onThreat
        started = true
        Talsec.start(config: TalsecConfig(
            appBundleIds: bundleIds,
            appTeamId: teamId,
            watcherMailAddress: watcherMail,
            isProd: isProd
        ))
    }

    public static func hasDetected(_ threat: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return detected.contains(threat)
    }

    static func receive(_ threat: SecurityThreat) {
        let name = stableName(threat)
        lock.lock()
        detected.insert(name)
        let callback = handler
        let severity: ShellsmithThreatSeverity
        if criticalThreats.contains(name) {
            severity = .critical
        } else if [.signature, .jailbreak, .debugger, .runtimeManipulation].contains(threat) {
            severity = .restrict
        } else {
            severity = .observe
        }
        lock.unlock()
        let event = ShellsmithThreatEvent(name: name, severity: severity)
        callback?(event)
        NotificationCenter.default.post(
            name: .shellsmithThreatDetected,
            object: nil,
            userInfo: ["threat": name, "severity": severity.rawValue]
        )
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
    r#"import DeviceCheck
import Foundation

@available(iOS 14.0, *)
public enum ShellsmithAppAttest {
    public static var isSupported: Bool { DCAppAttestService.shared.isSupported }

    public static func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.generateKey { keyId, error in
                if let keyId { continuation.resume(returning: keyId) }
                else { continuation.resume(throwing: error ?? ShellsmithAppAttestError.missingResult) }
            }
        }
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
}

public enum ShellsmithAppAttestError: Error {
    case missingResult
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
    use std::fs;
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
}
