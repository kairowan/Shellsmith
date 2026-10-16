#!/usr/bin/env python3
"""构建自有 Java/D8 APK，对指定设备执行基线、首次、缓存及覆盖安装回归；不自动选择设备。"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = r'''
package dev.mocika.shield.pvm2regression;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.lang.reflect.Method;

/** Java/D8 真实调用样本；同时检查被转换方法和保持 ART 的兼容边界。 */
public class CompatibilityActivity extends Activity {
    public interface Contract {
        int compute(int value);
        default int defaultValue(int value) { return value * 3; }
    }
    public static class Base { public int compute(int value) { return -1; } }
    public static class RulesView extends Base implements Contract {
        @Override public int compute(int value) { return value + 7; }
        public long compute(long value) { return value ^ 0x123456789abcdefL; }
        public Object self() { return this; }
        public Object identity(Object value) { return value; }
        public int[] identity(int[] value) { return value; }
        public boolean same(Object a, Object b) { return a == b; }
        public Object choose(Object a, Object b) { return a != null ? a : b; }
        protected int protectedValue(int value) { return value + 3; }
        private int privateValue(int value) { return value ^ 0x5a; }
        public static int staticValue(int value) { return value - 11; }
        public int divide(int value, int divisor) {
            try { return value / divisor; } catch (ArithmeticException error) { return -17; }
        }
        public long wideDivide(long value, long divisor) {
            try { return value / divisor; } catch (ArithmeticException error) { return -17L; }
        }
        public long wideRemainder(long value, long divisor) {
            try { return value % divisor; } catch (ArithmeticException error) { return -17L; }
        }
        public int nested(int divisor) {
            int value = 40;
            try {
                try { value = 40 / divisor; } catch (ArithmeticException error) { value = -17; }
            } finally { value += 3; }
            return value;
        }
        public int ordered(Throwable error) {
            try { throw error; }
            catch (IllegalArgumentException caught) { return 1; }
            catch (RuntimeException caught) { return 2; }
            catch (Exception caught) { return 3; }
            catch (Throwable caught) { return 4; }
        }
        public int multi(Throwable error) {
            try { throw error; }
            catch (IllegalArgumentException | NullPointerException caught) { return 1; }
            catch (RuntimeException caught) { return 2; }
            catch (Throwable caught) { return 3; }
        }
        public void rethrow(Throwable error) throws Throwable {
            try { throw error; } catch (Throwable caught) { throw caught; }
        }
        public void replace(Throwable original, Throwable replacement) throws Throwable {
            try { throw original; } finally { throw replacement; }
        }
        public int returnInFinally(int divisor) {
            try { return 12 / divisor; } finally { return 77; }
        }
        public Throwable catchReturn(Throwable error) {
            try { throw error; } catch (Throwable caught) { return caught; }
        }
        public Object finallyReference(Object input, Throwable error) throws Throwable {
            try { if (error != null) throw error; return input; } finally { input = null; }
        }
        public int loopCatch(int count) {
            int sum = 0;
            for (int i = 0; i < count; i++) {
                try { sum += 100 / (i - 2); } catch (ArithmeticException error) { sum ^= 5; }
            }
            return sum;
        }
        public int switchInCatch(int value, int divisor) {
            try { return value / divisor; }
            catch (ArithmeticException error) {
                switch (value) { case -1: return 31; case 0: return 43; case 1: return 59; default: return 71; }
            }
        }
        public double floating(double value) { return value * 1.5d + 2.0d; }
    }
    public static class ChildView extends RulesView {
        @Override public int compute(int value) { return value + 17; }
        @Override public Object self() { return this; }
    }
    public static class RejectedView extends Base {
        private int counter;
        public int stateful() { return ++counter; }
        public int callOther(int value) { return Math.abs(value); }
        public int superCompute(int value) { return super.compute(value); }
        public synchronized int locked() { return 5; }
        @Override public int hashCode() { return 13; }
        public native int nativeCall();
    }
    private int checks;
    private void check(boolean passed, String label) {
        if (!passed) throw new AssertionError(label);
        checks++;
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        try {
            RulesView parent = new RulesView(); ChildView child = new ChildView();
            Base base = child; Contract face = child; RulesView view = child;
            check(base.compute(5) == 22 && face.compute(5) == 22 && view.compute(5) == 22, "虚分派");
            check(face.defaultValue(5) == 15 && new Base().compute(5) == -1, "默认接口和父类");
            check(parent.self() == parent && child.self() == child, "接收者");
            Object first = new Object(), other = new Object(); int[] array = {1, 2};
            for (Object input : new Object[]{null, first, other, array, Integer.valueOf(3)}) {
                check(parent.identity(input) == input && parent.choose(null, input) == input, "引用与空值");
                check(parent.finallyReference(input, null) == input, "finally 引用存活");
                check(parent.same(input, input) && !parent.same(first, other), "引用身份");
            }
            check(parent.identity(array) == array && parent.identity((int[])null) == null, "数组透传");
            Method privateMethod = RulesView.class.getDeclaredMethod("privateValue", int.class);
            privateMethod.setAccessible(true);
            int[] ints = {Integer.MIN_VALUE, -10000, -3, -1, 0, 1, 2, 7, 10000, Integer.MAX_VALUE};
            long[] longs = {Long.MIN_VALUE, -10000000001L, -3L, -1L, 0L, 1L, 2L, Long.MAX_VALUE};
            for (int value : ints) {
                check(parent.compute(value) == value + 7 && parent.protectedValue(value) == value + 3, "整数与访问标志");
                check((Integer)privateMethod.invoke(parent, value) == (value ^ 0x5a) && RulesView.staticValue(value) == value - 11, "反射私有和静态");
                for (int divisor : ints) {
                    check(parent.divide(value, divisor) == (divisor == 0 ? -17 : value / divisor), "整数除法异常");
                    int caught = value == -1 ? 31 : value == 0 ? 43 : value == 1 ? 59 : 71;
                    check(parent.switchInCatch(value, divisor) == (divisor == 0 ? caught : value / divisor), "catch switch");
                }
                check(parent.nested(value) == (value == 0 ? -14 : 40 / value + 3), "嵌套清理");
                check(parent.returnInFinally(value) == 77, "finally 覆盖返回与异常");
            }
            for (long value : longs) {
                check(parent.compute(value) == (value ^ 0x123456789abcdefL), "宽值重载");
                for (long divisor : longs) {
                    check(parent.wideDivide(value, divisor) == (divisor == 0 ? -17L : value / divisor), "长整数除法");
                    check(parent.wideRemainder(value, divisor) == (divisor == 0 ? -17L : value % divisor), "长整数余数");
                }
            }
            Throwable[] errors = {null, new IllegalArgumentException(), new IllegalStateException(), new Exception(), new AssertionError()};
            for (int i = 0; i < errors.length; i++) {
                Throwable error = errors[i];
                check(parent.ordered(error) == (i == 1 ? 1 : i <= 2 ? 2 : i == 3 ? 3 : 4), "捕获顺序");
                check(parent.multi(error) == (i <= 1 ? 1 : i == 2 ? 2 : 3), "多类型捕获");
                Throwable returned = parent.catchReturn(error);
                check(error == null ? returned instanceof NullPointerException : returned == error, "捕获对象");
                try { parent.rethrow(error); throw new AssertionError("异常丢失"); }
                catch (Throwable caught) { check(error == null ? caught instanceof NullPointerException : caught == error, "重抛身份"); }
                if (error != null) {
                    try { parent.finallyReference(first, error); throw new AssertionError("异常丢失"); }
                    catch (Throwable caught) { check(caught == error, "finally 异常身份"); }
                }
                for (Throwable replacement : errors) {
                    try { parent.replace(error, replacement); throw new AssertionError("异常丢失"); }
                    catch (Throwable caught) { check(replacement == null ? caught instanceof NullPointerException : caught == replacement, "finally 替换异常"); }
                }
            }
            for (int count = 0; count < 30; count++) {
                int expected = 0;
                for (int i = 0; i < count; i++) expected = i == 2 ? expected ^ 5 : expected + 100 / (i - 2);
                check(parent.loopCatch(count) == expected, "循环异常汇合");
            }
            for (double value : new double[]{-Double.MAX_VALUE, -0.0d, 0.0d, Double.NaN, Double.POSITIVE_INFINITY, 3.25d})
                check(Double.doubleToLongBits(parent.floating(value)) == Double.doubleToLongBits(value * 1.5d + 2.0d), "浮点特殊值");
            RejectedView rejected = new RejectedView();
            check(rejected.stateful() == 1 && rejected.stateful() == 2 && rejected.callOther(-3) == 3, "状态和调用保留");
            check(rejected.superCompute(5) == -1 && rejected.locked() == 5 && rejected.hashCode() == 13, "super 同步与对象契约保留");
            Log.e("Pvm2Regression", "PVM2_REGRESSION_OK token=" + getIntent().getStringExtra("run_token")
                    + " checks=" + checks + " pages=" + android.system.Os.sysconf(android.system.OsConstants._SC_PAGESIZE));
        } catch (Throwable error) { throw new AssertionError("PVM2 回归失败 checks=" + checks, error); }
    }
}
'''

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--serial', action='append', default=[], help='明确指定本轮有权测试的设备，可重复传入；省略只构建和检查覆盖')
parser.add_argument('--output', type=Path, default=ROOT / 'target/pvm2-art-checks')
parser.add_argument('--without-resource-table', action='store_true', help='生成完全不带 resources.arsc 的 APK，默认保留合法空表')
args = parser.parse_args()
work = args.output.resolve()
work.mkdir(parents=True, exist_ok=True)
sdk_value = os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('ANDROID_HOME')
if not sdk_value:
    raise SystemExit('请设置 ANDROID_SDK_ROOT')
sdk = Path(sdk_value)
bt = sdk / 'build-tools/35.0.0'
android = sdk / 'platforms/android-35/android.jar'
cli = ROOT / 'target/release/shield'
env = dict(os.environ, SHIELD_TEST_KS_PASS='shellsmith-art-regression')
log = (work / 'commands.log').open('w')

def run(command):
    result = subprocess.run([str(x) for x in command], cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
    log.write(result.stdout + result.stderr); log.flush()
    if result.returncode:
        raise RuntimeError('命令失败，请查看 ' + str(work / 'commands.log'))
    return result.stdout

for name in ['classes', 'dex']:
    (work / name).mkdir(exist_ok=True)
(work / 'CompatibilityActivity.java').write_text(SOURCE)
package = 'dev.mocika.shield.pvm2regression'
(work / 'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="' + package + '"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35"/><application android:label="PVM2 ART 回归" android:allowBackup="false"><activity android:name=".CompatibilityActivity" android:exported="true"/></application></manifest>')
run([bt / 'aapt2', 'link', '-o', work / 'base.apk', '--manifest', work / 'AndroidManifest.xml', '-I', android])
run(['javac', '--release', '8', '-cp', android, '-d', work / 'classes', work / 'CompatibilityActivity.java'])
run(['jar', 'cf', work / 'classes.jar', '-C', work / 'classes', '.'])
run([bt / 'd8', '--release', '--lib', android, '--min-api', '23', '--output', work / 'dex', work / 'classes.jar'])
with zipfile.ZipFile(work / 'base.apk') as base, zipfile.ZipFile(work / 'input-unsigned.apk', 'w') as archive:
    for entry in base.infolist():
        if not args.without_resource_table or entry.filename != 'resources.arsc':
            archive.writestr(entry, base.read(entry.filename))
    archive.write(work / 'dex/classes.dex', 'classes.dex')
keystore = work / 'test.p12'
if not keystore.exists():
    run(['keytool', '-genkeypair', '-noprompt', '-keystore', keystore, '-storetype', 'PKCS12', '-storepass:env', 'SHIELD_TEST_KS_PASS', '-keypass:env', 'SHIELD_TEST_KS_PASS', '-alias', 'probe', '-keyalg', 'RSA', '-validity', '365', '-dname', 'CN=Shellsmith ART Test'])
keystore.chmod(0o600)
env['MOCIKA_SHIELD_KS_PASS'] = env['SHIELD_TEST_KS_PASS']

def sign(source, destination):
    run([cli, 'sign', '-i', work / source, '-o', work / destination, '--ks', keystore, '--key-alias', 'probe', '--ks-type', 'pkcs12', '--apksigner', ROOT / 'tools/apksigner.jar'])

sign('input-unsigned.apk', 'input.apk')
protect = [cli, 'protect', '-i', work / 'input.apk', '-o', work / 'protected.apk', '--resources', ROOT / 'shield-stub/build/outputs/resources/resources.zip', '--apktool', ROOT / 'tools/apktool_3.0.3.jar', '--apksigner', ROOT / 'tools/apksigner.jar', '--profile', 'strict', '--ai-resistance', 'high', '--environment-policy', 'compatible', '--xop-pvm2-packer', ROOT / 'tools/xop-pvm2-packer.jar']
for name in ['RulesView', 'ChildView', 'RejectedView']:
    protect += ['--xop-true-vmp-prefix', 'L' + package.replace('.', '/') + '/CompatibilityActivity$' + name + ';']
run(protect)
sign('protected.apk', 'protected-signed.apk')
report = json.loads((work / 'protected-signed.apk.protection.json').read_text())
assert report['output_sha256'] == hashlib.sha256((work / 'protected-signed.apk').read_bytes()).hexdigest()
counts = Counter()
for row in report['methods']:
    if '-><' in row['descriptor']:
        assert not row['artifact_verified'] and row['reason'] == 'initializer', row
    elif row['descriptor'].endswith('$RulesView;->defaultValue(I)I'):
        # D8 为默认接口方法生成转发桥；它应留在 ART，运行时仍须验证接口调用结果。
        assert not row['artifact_verified'] and row['reason'] == 'compiler_generated_bridge', row
    elif '$RejectedView;' in row['descriptor']:
        assert not row['artifact_verified'], row
        expected = {'stateful': 'ui_runtime_glue:non_leaf_instruction', 'callOther': 'ui_runtime_glue:non_leaf_instruction',
                    'superCompute': 'ui_runtime_glue:non_leaf_instruction', 'locked': 'ui_runtime_glue:synchronization',
                    'hashCode': 'ui_runtime_glue:virtual_contract', 'nativeCall': 'no_code'}
        name = row['descriptor'].split('->')[1].split('(')[0]
        assert row['reason'] == expected[name], row
    else:
        assert row['artifact_verified'], row
    counts['verified' if row['artifact_verified'] else row['reason']] += 1
assert counts['verified'] == 26 and len(report['methods']) == 36, counts
print('Java/D8 整包：26 个方法验证通过，3 个初始化方法、1 个 D8 桥接方法和 6 个明确不支持的方法保留。', flush=True)
results = {'coverage': dict(counts), 'apk_sha256': report['output_sha256'],
           'resource_table': 'absent' if args.without_resource_table else 'empty',
           'source_sha256': hashlib.sha256(SOURCE.encode()).hexdigest(), 'devices': []}
(work / 'result.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
for serial in args.serial:
    adb = [sdk / 'platform-tools/adb', '-s', serial]
    device = {'api': run(adb + ['shell', 'getprop', 'ro.build.version.sdk']).strip(),
              'abi': run(adb + ['shell', 'getprop', 'ro.product.cpu.abi']).strip(), 'scenarios': []}
    for scenario, apk in [('baseline', 'input.apk'), ('protected-first', 'protected-signed.apk'),
                          ('protected-cached', None), ('protected-update', 'protected-signed.apk'), ('baseline-restore', 'input.apk')]:
        if apk:
            assert 'Success' in run(adb + ['install', '-r', work / apk])
        run(adb + ['shell', 'am', 'force-stop', package])
        # 只读取本次启动之后的日志；不清除设备日志或现有业务数据。
        stamp = run(adb + ['shell', 'date', "'+%m-%d %H:%M:%S.000'"]).strip()
        token = uuid.uuid4().hex
        marker = 'PVM2_REGRESSION_OK token=' + token + ' checks='
        run(adb + ['shell', 'am', 'start', '-W', '-n', package + '/.CompatibilityActivity', '--es', 'run_token', token])
        logs = ''
        for _ in range(15):
            logs = run(adb + ['logcat', '-d', '-T', stamp, '-s', 'Pvm2Regression:E', 'AndroidRuntime:E', '*:S'])
            if marker in logs or 'FATAL EXCEPTION' in logs:
                break
            time.sleep(1)
        path = work / ('api' + device['api'] + '-' + scenario + '.log')
        path.write_text(logs)
        match = re.search(re.escape(marker) + r'(\d+) pages=(\d+)', logs)
        assert match and 'FATAL EXCEPTION' not in logs, str(path)
        checks = int(match.group(1))
        assert checks == 482, checks
        device['page_size'] = int(match.group(2))
        assert run(adb + ['shell', 'pidof', package]).strip(), str(path)
        device['scenarios'].append({'name': scenario, 'checks': checks})
        print('Android API ' + device['api'] + ' ' + scenario + '：' + str(checks) + ' 项执行检查通过', flush=True)
    results['devices'].append(device)
    (work / 'result.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
