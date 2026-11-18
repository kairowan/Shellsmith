use anyhow::{ensure, Result};
use shield_core::protected_resources::PreparedResources;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
#[ignore = "需要 JDK 和 macOS Swift CryptoKit"]
fn rust_产物由_java_和_swift_验证() -> Result<()> {
    let fixture = tempfile::tempdir()?;
    let root = fixture.path();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = root.join("manifest.json");
    let plaintext: Vec<u8> = (0..65_536 + 17)
        .map(|index| 0x42 ^ (index % 251) as u8)
        .collect();
    fs::write(root.join("rules.json"), plaintext)?;
    fs::write(&manifest, br#"{"version":1,"resources":[{"id":"rules","group":"policy","source":"rules.json","version":3,"read":"stream"}]}"#)?;
    let destination = root.join("sealed");
    let prepared = PreparedResources::prepare(&manifest, root, &destination)?;
    fs::write(root.join("build-id"), prepared.build_id())?;
    fs::write(
        root.join("fixture-key"),
        prepared.group_keys().next().unwrap().1,
    )?;
    let sealed = fs::read(destination.join("rules.ssr"))?;
    for (name, data) in [
        ("truncated", sealed[..sealed.len() - 1].to_vec()),
        ("extended", [&sealed[..], &[0]].concat()),
        ("tampered", {
            let mut changed = sealed.clone();
            let last = changed.len() - 1;
            changed[last] ^= 1;
            changed
        }),
    ] {
        fs::write(root.join(name), data)?;
    }
    let javac = Command::new("javac")
        .arg("-d")
        .arg(root)
        .arg(repo.join(
            "shield-stub/src/main/java/dev/mocika/shield/loader/ProtectedResourceStream.java",
        ))
        .arg(repo.join("tests/fixtures/protected-resource/ReaderCheck.java"))
        .status()?;
    ensure!(javac.success(), "Java 资源夹具编译失败");
    let java = Command::new("java")
        .arg("-ea")
        .arg("-cp")
        .arg(root)
        .arg("dev.mocika.shield.loader.ReaderCheck")
        .arg(root)
        .status()?;
    ensure!(java.success(), "Java 资源读取回归失败");
    let check = root.join("swift-check");
    let swiftc = Command::new("swiftc")
        .arg(repo.join("crates/shield-ios/src/ProtectedResourceReader.swift"))
        .arg(repo.join("tests/fixtures/protected-resource/main.swift"))
        .arg("-o")
        .arg(&check)
        .status()?;
    ensure!(swiftc.success(), "Swift 资源夹具编译失败");
    let swift = Command::new(check).arg(root).status()?;
    ensure!(swift.success(), "Swift 资源读取回归失败");
    Ok(())
}
