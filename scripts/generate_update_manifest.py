#!/usr/bin/env python3
"""仅在三平台更新包及版本签名均已上传后生成 Tauri 静态更新清单。"""

import argparse
import base64
import json
import re
from pathlib import Path
from urllib.parse import quote, unquote


def generate_manifest(version, assets, signatures, notes, *, draft_tag=None):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
        raise ValueError("版本号无效")
    if draft_tag is not None and draft_tag != f"v{version}":
        raise ValueError("草稿版本与更新版本不匹配")
    prefix = f"Shellsmith_{version}"
    packages = {
        "darwin-aarch64": f"{prefix}_macos_universal.app.tar.gz",
        "darwin-x86_64": f"{prefix}_macos_universal.app.tar.gz",
        "windows-x86_64": f"{prefix}_windows_x64_setup.exe",
        "linux-x86_64": f"{prefix}_linux_amd64.AppImage",
    }
    by_name = {asset["name"]: asset for asset in assets}
    platforms = {}
    for platform, name in packages.items():
        url = f"https://github.com/kairowan/Shellsmith/releases/download/v{quote(version, safe='')}/{quote(name, safe='')}"
        for filename, expected_url in [(name, url), (name + ".sig", url + ".sig")]:
            asset = by_name.get(filename)
            if not asset or asset.get("size", 0) <= 0 or asset.get("state") != "uploaded":
                raise ValueError(f"缺少完整上传的更新产物：{filename}")
            actual_url = unquote(asset.get("url", ""))
            # GitHub 草稿即使已有 tag，仍返回 untagged 临时地址；清单只写正式地址。
            draft_url = draft_tag is not None and re.fullmatch(
                rf"https://github\.com/kairowan/Shellsmith/releases/download/untagged-[0-9a-f]+/{re.escape(filename)}",
                actual_url,
            )
            if actual_url != unquote(expected_url) and not draft_url:
                raise ValueError(f"更新产物地址与版本不匹配：{filename}")
        signature = (signatures / (name + ".sig")).read_text(encoding="utf-8").strip()
        lines = base64.b64decode(signature, validate=True).decode("utf-8").splitlines()
        if len(lines) != 4 or not lines[2].startswith("trusted comment: "):
            raise ValueError(f"更新签名格式无效：{name}")
        fields = lines[2].removeprefix("trusted comment: ").split("\t")
        if [field for field in fields if field.startswith("version:")] != [f"version:{version}"]:
            raise ValueError(f"签名未绑定当前版本：{name}")
        # 这里只检查发布结构；客户端仍须使用内置公钥验证包与可信注释的密码学签名。
        platforms[platform] = {"url": url, "signature": signature}
    return {"version": version, "notes": notes, "platforms": platforms}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version")
    parser.add_argument("assets", type=Path)
    parser.add_argument("signatures", type=Path)
    parser.add_argument("notes", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    release = json.loads(args.assets.read_text(encoding="utf-8"))
    if release.get("tagName") != f"v{args.version}":
        raise ValueError("Release tag 与更新版本不匹配")
    manifest = generate_manifest(
        args.version, release["assets"],
        args.signatures, args.notes.read_text(encoding="utf-8"),
        draft_tag=release["tagName"] if release.get("isDraft") is True else None,
    )
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
