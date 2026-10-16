#!/usr/bin/env python3
"""使用生产 C++ 源码检查 PVM2 生命周期；需要 JDK、Clang 和 C++20。"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CPP = ROOT / 'third_party/xopprotector/native/src/main/cpp'
java = os.environ.get('JAVA_HOME')
if not java:
    result = subprocess.run(['java', '-XshowSettings:properties', '-version'], capture_output=True, text=True, check=True)
    java = next(line.split('=', 1)[1].strip() for line in result.stderr.splitlines() if 'java.home =' in line)
java = Path(java)
platform = 'darwin' if sys.platform == 'darwin' else 'linux'
with tempfile.TemporaryDirectory(prefix='pvm2-runtime-') as temp:
    temp = Path(temp)
    (temp / 'android').mkdir()
    (temp / 'android/log.h').write_text('''#pragma once
#define ANDROID_LOG_ERROR 6
static inline int __android_log_print(int, const char*, const char*, ...) { return 0; }
''')
    jar = ROOT / 'tools/xop-pvm2-packer.jar'
    subprocess.run([sys.executable, str(ROOT / 'scripts/build_pvm2_packer.py'), '--check'], check=True)
    subprocess.run(['javac', '--release', '17', '-cp', str(jar), '-d', str(temp),
                    str(ROOT / 'tests/java/com/yqsh/protector/packer/Pvm2ProtectionCheck.java'),
                    str(ROOT / 'tests/java/com/yqsh/protector/packer/Pvm2RuntimeImages.java')], check=True)
    subprocess.run(['java', '-cp', str(temp) + os.pathsep + str(jar),
                    'com.yqsh.protector.packer.Pvm2RuntimeImages', str(temp)], check=True)
    exe = temp / 'check'
    sanitizer = os.environ.get('PVM2_SANITIZER', 'address,undefined')
    cmd = [os.environ.get('CXX', 'clang++'), '-std=c++20', '-O2', '-g', '-UNDEBUG',
           '-pthread', '-fno-omit-frame-pointer', '-I' + str(temp), '-I' + str(CPP),
           '-I' + str(java / 'include'), '-I' + str(java / 'include' / platform)]
    # 断言在优化构建中保留；关闭生产调试日志，避免输出虚拟指令。
    (temp / 'android/log.h').write_text((temp / 'android/log.h').read_text() + '\n#define ANDROID_LOG_DEBUG 3\n#define ANDROID_LOG_INFO 4\n#define ANDROID_LOG_WARN 5\n')
    if sanitizer: cmd += ['-fsanitize=' + sanitizer]
    if os.environ.get('MOCIKA_RUNTIME_PROFILE') == '1': cmd += ['-DMOCIKA_PVM2_PROFILE=1']
    cmd += [str(ROOT / 'tests/native/pvm2_runtime_check.cpp'),
            str(ROOT / 'shield-stub/src/main/rust/src/xop_pvm2_bridge.cpp')]
    cmd += [str(CPP / s) for s in ['common/runtime_state.cpp', 'codeitem/multi_dex_code.cpp', 'crypto/aes.cpp', 'vm/pvm2_format.cpp']]
    cmd += ['-L' + str(java / 'lib/server'), '-Wl,-rpath,' + str(java / 'lib/server'), '-ljvm', '-o', str(exe)]
    subprocess.run(cmd, check=True)
    env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1')
    # JVM 自有分配及进程级 JNI 类缓存不用于解释器泄漏判定；对象生命周期由断言检查。
    subprocess.run([str(exe), 'block-before-init'], check=True, env=env)
    subprocess.run([str(exe), str(temp)], check=True, env=env)
