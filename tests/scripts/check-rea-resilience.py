#!/usr/bin/env python3
"""用固定版本 REA 与仓库白盒恢复检查分别验证授权 APK；不安装工具、不连接设备。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
JADX_SHA256 = '6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75'
DIAGNOSTICS = (b'PVM2 bad ', b'PVM2 unknown op', b'unsupported code.bin version',
               b'VMP bad dex', b'VMP argument count mismatch', b'VMP refused by RASP',
               b'MOCIKA_PVM2_PROFILE')


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rea', type=Path, required=True, help='rea-agents 6.7.0 的 scripts/rea.mjs')
    parser.add_argument('--jadx-jar', type=Path, required=True)
    parser.add_argument('--input-apk', type=Path, required=True)
    parser.add_argument('--protected-apk', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True, help='与加固 APK 哈希匹配的逐方法报告')
    parser.add_argument('--output', type=Path, required=True, help='尚不存在的本地证据目录，包含业务标识')
    parser.add_argument('--class-query', required=True)
    parser.add_argument('--method', action='append', required=True, help='REA 类名#方法名；只接受无重载的抽样方法，可重复')
    parser.add_argument('--require-private-diagnostics', action='store_true')
    args = parser.parse_args()
    for name in ('rea', 'jadx_jar', 'input_apk', 'protected_apk', 'report'):
        path = getattr(args, name).resolve(strict=True)
        if not path.is_file():
            raise ValueError('输入必须是文件：' + name)
        setattr(args, name, path)
    if digest(args.jadx_jar) != JADX_SHA256:
        raise ValueError('JADX 与 REA 固定元数据不匹配')
    rea = ['node', str(args.rea)]
    version = subprocess.check_output(rea + ['--version'], text=True, timeout=30).strip()
    if version != '6.7.0':
        raise ValueError('本回归固定 REA 6.7.0；升级后需重新核验结果契约')
    report = json.loads(args.report.read_text(encoding='utf-8'))
    if (report['output_sha256'] != digest(args.protected_apk)
            or report['build']['input_sha256'] != digest(args.input_apk)):
        raise ValueError('报告与输入/输出 APK 不匹配')
    work = args.output.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    summary = {'rea_version': version, 'jadx_sha256': JADX_SHA256,
               'input_sha256': digest(args.input_apk), 'output_sha256': digest(args.protected_apk),
               'status': 'incomplete', 'semantic_reconstruction': 'not_evaluated',
               'dynamic_instrumentation': 'not_evaluated'}
    env = dict(os.environ, REA_JADX_MCP_JAR=str(args.jadx_jar))

    def inspect(label, apk, command, *selection):
        with (work / (label + '.json')).open('w') as out, (work / (label + '.log')).open('w') as err:
            subprocess.run(rea + [command, str(apk), *selection, '--json'],
                           stdout=out, stderr=err, env=env, check=True, timeout=180)
        evidence = json.loads((work / (label + '.json')).read_text(encoding='utf-8'))
        if (evidence['subject']['digest']['sha256'] != digest(apk)
                or evidence['normalized_result']['engine']['artifact_sha256'] != JADX_SHA256):
            raise ValueError('REA 证据未绑定本次产物或指定引擎')
        return evidence['normalized_result']

    try:
        direct = inspect('direct-classes', args.protected_apk, 'search-android-classes', args.class_query)
        if direct['coverage'] != 'complete':
            raise ValueError('REA 类搜索未完成，不能判定保护效果')
        summary['direct_class_matches'] = len(direct['matches'])
        # 白盒恢复与 REA 分开计时/记证据，不把仓库私有知识冒充 REA 自动还原能力。
        classes = work / 'checker'
        classes.mkdir()
        jar = ROOT / 'tools/xop-pvm2-packer.jar'
        sources = ROOT / 'tests/java/com/yqsh/protector/packer'
        with (work / 'recovery.log').open('w') as log:
            subprocess.run(['javac', '--release', '17', '-cp', str(jar), '-d', str(classes),
                            *[str(sources / (name + '.java')) for name in
                              ('Pvm2ProtectionCheck', 'Pvm2RuntimeImages', 'ApkRecoveryCheck')]],
                           stdout=log, stderr=log, check=True, timeout=120)
            zstd = shutil.which('zstd')
            if not zstd:
                raise ValueError('缺少本地 zstd，不能把工具缺失视为抗还原通过')
            subprocess.run(['java', '-ea', '-cp', str(classes) + os.pathsep + str(jar),
                            'com.yqsh.protector.packer.ApkRecoveryCheck', str(args.protected_apk),
                            str(work / 'recovered'), zstd, str(args.report)],
                           stdout=log, stderr=log, check=True, timeout=180)
        recovery = json.loads((work / 'recovered/recovery.json').read_text(encoding='utf-8'))
        verified = sum(row['artifact_verified'] for row in report['methods'])
        if verified == 0 or verified != recovery['verified_trampolines']:
            raise ValueError('逐方法报告与恢复跳板数量不一致')
        summary.update(selected_methods=len(report['methods']), verified_methods=verified,
                       recovered_images=len(recovery['recovered_images']),
                       verified_trampolines=recovery['verified_trampolines'],
                       apk_only_payload_recovery='recovered', recovery_ms=recovery['elapsed_ms'])
        # 只从加固 APK 和恢复出的 DEX 重建静态分析输入，不借用原包代码，不安装此未签名包。
        recovered_apk = work / 'recovered-for-analysis.apk'
        with zipfile.ZipFile(args.protected_apk) as original, zipfile.ZipFile(recovered_apk, 'w') as rebuilt:
            for item in original.infolist():
                if re.fullmatch(r'classes\d*\.dex', item.filename) or item.filename.startswith('META-INF/'):
                    continue
                rebuilt.writestr(item, original.read(item))
            for name in recovery['entries']:
                if re.fullmatch(r'classes\d*\.dex', name):
                    rebuilt.write(work / 'recovered' / name, name)
        samples = []
        protected_methods = {row['descriptor'].split(';->', 1)[0][1:].replace('/', '.').replace('$', '.')
                             + '#' + row['descriptor'].split(';->', 1)[1]
                             for row in report['methods'] if row['artifact_verified']}
        for index, selection in enumerate(args.method):
            owner, method = selection.rsplit('#', 1)
            before = inspect('method-%d-before' % index, args.input_apk, 'inspect-android-method', owner, method)
            after = inspect('method-%d-recovered' % index, recovered_apk, 'inspect-android-method', owner, method)
            for evidence in (before, after):
                if evidence['body_status'] != 'available' or evidence['source']['status'] != 'complete':
                    raise ValueError('REA 方法体读取不完整，不能判定语义是否隐藏')
            if (selection + before['method']['dex_descriptor'] not in protected_methods
                    or before['method']['dex_descriptor'] != after['method']['dex_descriptor']):
                raise ValueError('抽样方法没有对应到同签名的已验证保护方法')
            samples.append({'class': owner, 'method': method,
                            'same_decompiled_text': before['source']['text'] == after['source']['text'],
                            'before_representation': before['representation'], 'after_representation': after['representation']})
        summary['method_samples'] = samples
        with zipfile.ZipFile(args.protected_apk) as apk:
            summary['native_diagnostic_matches'] = {}
            for name in apk.namelist():
                if name.startswith('lib/') and name.endswith('.so'):
                    binary = apk.read(name)
                    summary['native_diagnostic_matches'][name] = sum(binary.count(marker) for marker in DIAGNOSTICS)
        if args.require_private_diagnostics:
            if not summary['native_diagnostic_matches']:
                raise ValueError('未检查到 Native 库，不能判定发布诊断检查通过')
            if any(summary['native_diagnostic_matches'].values()):
                raise ValueError('产物仍携带内部诊断或性能采样文本')
        summary['status'] = 'complete'
        print('REA 回归完成；白盒已恢复 %d 个镜像，不能宣称 APK 载荷保密。' % summary['recovered_images'])
    except Exception:
        summary['status'] = 'error'
        raise
    finally:
        (work / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
