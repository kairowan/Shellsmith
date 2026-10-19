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
    public static class Base {
        public int compute(int value) { return -1; }
        public int sum(int a, int b, int c, int d, int e, int f) { return -2; }
    }
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
        private Object state;
        private int count;
        private long wide;
        private double decimal;
        private float fraction;
        private boolean enabled;
        private byte small;
        private short medium;
        private char character;
        private static Object shared;
        public Object fields(Object value) {
            state = value; shared = value; count++; wide = -1234567890123L;
            decimal = -3.25d; fraction = 1.5f; enabled = true; small = -7; medium = -1234; character = '\ufffe';
            if (wide != -1234567890123L || decimal != -3.25d || fraction != 1.5f || !enabled
                    || small != -7 || medium != -1234 || character != '\ufffe' || shared != value)
                throw new AssertionError("字段损坏");
            return state;
        }
        public String text() { return "中文\u0000\ud83d\ude00"; }
        public Object construct(Object value) { return new Holder(value).get(); }
        public int calls(Contract other, int value) {
            return other.compute(value) + privateValue(value) + staticValue(value) + Math.abs(value);
        }
        public String nullable(Object value, boolean clear) {
            if (clear) value = null;
            try { return value.toString(); } catch (NullPointerException error) { return "null"; }
        }
        public int invokeCatch(Holder value) {
            try { return value.fail(); } catch (IllegalArgumentException error) { return 91; }
            catch (NullPointerException error) { return 92; } finally { count++; }
        }
        public Object lockedBlock(Object lock, Object value, boolean fail) {
            synchronized (lock) {
                state = value; count++;
                if (fail) throw new IllegalStateException("测试异常");
                return state;
            }
        }
        public Object[] arrays(Object value) {
            Object[] result = new Object[]{value, this, null};
            int[] numbers = new int[]{1, 2, 3};
            numbers[1] += numbers[0];
            result[2] = Integer.valueOf(numbers[1]);
            return result;
        }
        public Object framework(android.content.Context context) {
            android.widget.TextView view = new android.widget.TextView(context);
            view.setText(text()); view.setTag(this);
            return view;
        }
        public long invokeWide(Holder value, long a, double b, float c) { return value.wide(a, b, c); }
        public int recursive(int value) { return value <= 0 ? 1 : value * recursive(value - 1); }
        public int interfaceDefault(Contract value) { return value.defaultValue(11); }
        public int defaultSuper(int value) { return Contract.super.defaultValue(value); }
        @Override public int sum(int a, int b, int c, int d, int e, int f) { return a+b+c+d+e+f; }
        /* LARGE_METHOD */

    }
    public static class Holder {
        final Object value;
        Holder(Object value) { this.value = value; }
        Object get() { return value; }
        int fail() { throw new IllegalArgumentException("测试异常"); }
        long wide(long a, double b, float c) { return a + (long)b + (long)c; }
    }
    public static class ChildView extends RulesView {
        @Override public int compute(int value) { return value + 17; }
        @Override public Object self() { return this; }
        public int parentCompute(int value) { return super.compute(value); }
        public int parentMany(int a, int b, int c, int d, int e, int f) { return super.sum(a,b,c,d,e,f); }
    }
    public static class GrandChild extends ChildView {
        @Override public int compute(int value) { return value + 100; }
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

            for (Object input : new Object[]{null, first, array, parent}) {
                check(parent.fields(input) == input && parent.construct(input) == input, "对象状态与构造");
                Object[] values = parent.arrays(input);
                check(values[0] == input && values[1] == parent && values[2].equals(3), "对象和整数数组");
                check(parent.nullable(input, true).equals("null"), "分支空接收者捕获");
            }
            check(parent.text() == "中文\u0000\ud83d\ude00", "字符串编码与驻留身份");
            check(parent.text().length() == 5 && parent.text().charAt(2) == 0, "字符串空字符和代理对");
            check(parent.calls(child, 7) == (24 + (7 ^ 0x5a) - 4 + 7), "接口私有静态嵌套调用");
            check(parent.nullable("value", false).equals("value") && parent.nullable(null, false).equals("null"), "调用异常语义");
            check(parent.invokeCatch(new Holder(first)) == 91 && parent.invokeCatch(null) == 92, "调用异常传播及清理");
            check(parent.invokeWide(new Holder(first), Long.MIN_VALUE, 12.75d, -2.5f) == Long.MIN_VALUE + 10, "宽参数调用");
            check(parent.recursive(6) == 720 && parent.interfaceDefault(child) == 33, "递归与默认接口调用");
            check(child.parentCompute(5) == 12, "父类非虚分派");
            for (int value : ints) {
                int expected = value;
                for (int i = 0; i < 160; i++) expected = (expected * 31) ^ i;
                check(parent.large(value) == expected, "超过旧代码长度上限的方法");
            }
            Object lock = new Object();
            check(parent.lockedBlock(lock, first, false) == first, "锁内对象状态");
            try { parent.lockedBlock(lock, other, true); throw new AssertionError("异常丢失"); }
            catch (IllegalStateException expected) { check(parent.fields(first) == first, "锁异常传播"); }
            Thread contender = new Thread(() -> { synchronized (lock) { } });
            contender.start(); contender.join(2000); check(!contender.isAlive(), "异常退出释放锁");
            try { parent.lockedBlock(null, first, false); throw new AssertionError("空锁未抛出"); }
            catch (NullPointerException expected) { check(true, "空锁异常"); }
            java.lang.reflect.Field counter = RulesView.class.getDeclaredField("count");
            counter.setAccessible(true);
            int before = counter.getInt(parent);
            Thread[] workers = new Thread[4];
            for (int i = 0; i < workers.length; i++) {
                workers[i] = new Thread(() -> { for (int j = 0; j < 200; j++) parent.lockedBlock(lock, first, false); });
                workers[i].start();
            }
            for (Thread worker : workers) { worker.join(5000); check(!worker.isAlive(), "竞争线程完成"); }
            check(counter.getInt(parent) == before + 800, "跨线程同步块状态一致");
            android.widget.TextView widget = (android.widget.TextView)parent.framework(this);
            check(widget.getTag() == parent && widget.getText().toString().equals(parent.text()), "真实框架对象调用");
            RejectedView rejected = new RejectedView();
            check(rejected.stateful() == 1 && rejected.stateful() == 2 && rejected.callOther(-3) == 3, "状态和调用保留");
            check(rejected.superCompute(5) == -1 && rejected.locked() == 5 && rejected.hashCode() == 13, "super 同步与对象契约保留");
            check(new GrandChild().parentCompute(5) == 12, "祖先引用按声明父类分派");
            check(new GrandChild().parentMany(1,2,3,4,5,6) == 21, "range 父类调用");
            check(parent.defaultSuper(7) == 21, "接口默认父实现");
            Log.e("Pvm2Regression", "PVM2_REGRESSION_OK token=" + getIntent().getStringExtra("run_token")
                    + " checks=" + checks + " pages=" + android.system.Os.sysconf(android.system.OsConstants._SC_PAGESIZE));
        } catch (Throwable error) { throw new AssertionError("PVM2 回归失败 checks=" + checks, error); }
    }
}
'''

SOURCE = SOURCE.replace('/* LARGE_METHOD */', 'public int large(int value) {\n' + '\n'.join('value = (value * 31) ^ ' + str(i) + ';' for i in range(160)) + '\nreturn value; }')

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--serial', action='append', default=[], help='明确指定本轮有权测试的设备，可重复传入；省略只构建和检查覆盖')
parser.add_argument('--output', type=Path, default=ROOT / 'target/pvm2-art-checks')
parser.add_argument('--min-api', type=int, choices=[23, 26], default=23, help='23 验证 D8 脱糖，26 验证原生接口默认方法')
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
run([bt / 'd8', '--release', '--lib', android, '--min-api', str(args.min_api), '--output', work / 'dex', work / 'classes.jar'])
# 将合法 super 引用规范到祖先，覆盖混淆器可能产生的引用；基线也使用同一 DEX。
(work / 'RewriteSuper.java').write_text(r'''import java.nio.file.*;
import java.util.*;
import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.dexbacked.*;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.iface.instruction.*;
import com.android.tools.smali.dexlib2.iface.instruction.formats.*;
import com.android.tools.smali.dexlib2.immutable.instruction.*;
import com.android.tools.smali.dexlib2.immutable.reference.*;
import com.android.tools.smali.dexlib2.rewriter.*;
import com.android.tools.smali.dexlib2.writer.pool.*;
import com.android.tools.smali.dexlib2.writer.io.*;
public class RewriteSuper {
  public static void main(String[] args) throws Exception {
    var dex = new DexBackedDexFile(Opcodes.getDefault(), Files.readAllBytes(Path.of(args[0])));
    int[] changed = {0, 0};
    var rewriter = new DexRewriter(new RewriterModule() {
      public Rewriter<Instruction> getInstructionRewriter(Rewriters rewriters) {
        return instruction -> {
          if (instruction.getOpcode() == Opcode.INVOKE_SUPER || instruction.getOpcode() == Opcode.INVOKE_SUPER_RANGE) {
            var method = (com.android.tools.smali.dexlib2.iface.reference.MethodReference)((ReferenceInstruction)instruction).getReference();
            if (method.getDefiningClass().endsWith("$RulesView;")) {
              var ref = new ImmutableMethodReference(method.getDefiningClass().replace("$RulesView;", "$Base;"), method.getName(), method.getParameterTypes(), method.getReturnType());
              if (instruction instanceof Instruction35c i) {
                changed[0]++;
                return new ImmutableInstruction35c(i.getOpcode(), i.getRegisterCount(), i.getRegisterC(), i.getRegisterD(), i.getRegisterE(), i.getRegisterF(), i.getRegisterG(), ref);
              }
              var i = (Instruction3rc)instruction; changed[1]++;
              return new ImmutableInstruction3rc(i.getOpcode(), i.getStartRegister(), i.getRegisterCount(), ref);
            }
          }
          return instruction;
        };
      }
    });
    var pool = new DexPool(Opcodes.getDefault());
    for (var cls : rewriter.getDexFileRewriter().rewrite(dex).getClasses()) pool.internClass(cls);
    assert changed[0] > 0 && changed[1] > 0 : Arrays.toString(changed);
    var output = new FileDataStore(Path.of(args[0]).toFile()); try { pool.writeTo(output); } finally { output.close(); }
  }
}''')
run(['javac', '--release', '17', '-cp', ROOT / 'tools/xop-pvm2-packer.jar', '-d', work, work / 'RewriteSuper.java'])
run(['java', '-ea', '-cp', str(work) + os.pathsep + str(ROOT / 'tools/xop-pvm2-packer.jar'), 'RewriteSuper', work / 'dex/classes.dex'])
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
assert any(row['descriptor'].endswith('->large(I)I') and row['input_instruction_bytes'] > 1024 and row['artifact_verified'] for row in report['methods'])
counts = Counter()
for row in report['methods']:
    if '-><' in row['descriptor']:
        assert not row['artifact_verified'] and row['reason'] == 'initializer', row
    elif row['descriptor'].endswith('$RulesView;->defaultValue(I)I'):
        # D8 为默认接口方法生成转发桥；它应留在 ART，运行时仍须验证接口调用结果。
        assert not row['artifact_verified'] and row['reason'] == 'compiler_generated_bridge', row
    elif '$RejectedView;' in row['descriptor'] and row['descriptor'].split('->')[1].split('(')[0] not in ['stateful', 'callOther', 'superCompute']:
        assert not row['artifact_verified'], row
        expected = {'locked': 'ui_runtime_glue:synchronization',
                    'hashCode': 'ui_runtime_glue:virtual_contract', 'nativeCall': 'no_code'}
        name = row['descriptor'].split('->')[1].split('(')[0]
        assert row['reason'] == expected[name], row
    else:
        assert row['artifact_verified'], row
    counts['verified' if row['artifact_verified'] else row['reason']] += 1
assert counts['verified'] == 46 and len(report['methods']) == (53 if args.min_api == 23 else 52), counts
print('Java/D8 整包：46 个方法验证通过，初始化、桥接、同步声明和特殊对象契约保留。', flush=True)
results = {'coverage': dict(counts), 'apk_sha256': report['output_sha256'],
           'resource_table': 'absent' if args.without_resource_table else 'empty', 'min_api': args.min_api,
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
        assert checks == 525, checks
        device['page_size'] = int(match.group(2))
        assert run(adb + ['shell', 'pidof', package]).strip(), str(path)
        device['scenarios'].append({'name': scenario, 'checks': checks})
        print('Android API ' + device['api'] + ' ' + scenario + '：' + str(checks) + ' 项执行检查通过', flush=True)
    results['devices'].append(device)
    (work / 'result.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')
