#!/usr/bin/env python3
"""运行真实 Swift 协议与状态机；只在临时副本替换 Apple 证明和 URLSession 传输。"""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = root / "crates/shield-ios/src"
with tempfile.TemporaryDirectory(prefix="shellsmith-risk-check-") as temporary:
    work = Path(temporary)
    authorization = (source / "ProtectedResourceAuthorization.swift").read_text().replace("private ", "")
    authorization = authorization.replace("URLSession(configuration: .ephemeral", "URLSession(configuration: RiskHarness.sessionConfiguration()")
    authorization = authorization.replace('FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]',
                                          'URL(fileURLWithPath: ProcessInfo.processInfo.environment["RISK_CHECK_STORE"]!)')
    authorization += '''\nextension ResourceAuthorization {
    func forceRiskRetry() async {
        riskRetry?.cancel(); riskRetry = nil
        for id in Array(riskScopes.keys) { riskScopes[id]?.next = 0 }
        await flushRisk()
    }
}\n'''
    (work / "Authorization.swift").write_text(authorization)
    (work / "main.swift").write_text((root / "tests/fixtures/risk-events/main.swift").read_text())
    files = [work / "main.swift", work / "Authorization.swift", source / "RiskEvent.swift",
             source / "ProtectedResourceReader.swift", source / "ProtectedResourceClock.swift"]
    environment = dict(os.environ, DEVELOPER_DIR="/Library/Developer/CommandLineTools", RISK_CHECK_STORE=str(work / "store"))
    subprocess.run(["swiftc", *map(str, files), "-o", str(work / "check")], env=environment, check=True)
    subprocess.run([str(work / "check"), str(root / "tests/fixtures/risk-events/risk-event-vector.json")], env=environment, check=True)
