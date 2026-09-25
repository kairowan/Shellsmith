use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let vars: &[(&str, &str)] = &[
        ("STUB_BINLOADER_CLASS", "dev/mocika/shield/loader/Ld"),
        ("STUB_METHOD_INJECT_DEX", "p"),
        ("STUB_METHOD_EXTRACT_DECRYPT", "q"),
        ("STUB_METHOD_CHECK_ENV", "r"),
        ("STUB_METHOD_GET_SIG", "getSignatureSha256"),
        ("STUB_METHOD_XOP_INTERPRET", "v"),
        ("STUB_METHOD_DECRYPT_ASSET", "u"),
        ("STUB_METHOD_NATIVE_SO_KEYS", "w"),
        ("STUB_METHOD_DECRYPT_SO", "x"),
    ];
    for (key, default) in vars {
        println!("cargo:rerun-if-env-changed={key}");
        let value = env::var(key).unwrap_or_else(|_| default.to_string());
        println!("cargo:rustc-env={key}={value}");
    }

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let target = env::var("TARGET").unwrap_or_default();
    let xop_disabled = env::var("CARGO_PKG_NAME").as_deref() == Ok("mocikashield-api19");
    if !target.contains("android") || xop_disabled {
        let stub = if xop_disabled {
            manifest.join("../../src/main/rust/src/xop_pvm2_host_stub.c")
        } else {
            manifest.join("src/xop_pvm2_host_stub.c")
        };
        cc::Build::new().file(stub).compile("mocika_xop_pvm2");
        return;
    }

    let xop_root = env::var_os("MOCIKA_XOP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest.join("../../../../../XopProtector"));
    let cpp = xop_root.join("native/src/main/cpp");
    if !cpp.join("vm/pvm2_interp.cpp").is_file() {
        panic!(
            "Xop PVM2 sources not found at {} (set MOCIKA_XOP_ROOT)",
            xop_root.display()
        );
    }
    let sources = [
        "common/runtime_state.cpp",
        "codeitem/multi_dex_code.cpp",
        "crypto/aes.cpp",
        "vm/pvm2_format.cpp",
        "vm/pvm2_interp.cpp",
    ];
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .std("c++20")
        .cpp_link_stdlib("c++_static")
        .include(&cpp)
        .file(manifest.join("src/xop_pvm2_bridge.cpp"))
        .flag_if_supported("-fvisibility=hidden")
        .flag_if_supported("-ffunction-sections")
        .flag_if_supported("-fdata-sections")
        .define("NDEBUG", None)
        .warnings(false);
    for source in &sources {
        build.file(cpp.join(source));
    }
    build.compile("mocika_xop_pvm2");
    // cc only emits -lc++_static. The NDK keeps RTTI/exception/new-delete in
    // separate archives, so a cdylib can otherwise link with unresolved C++
    // symbols and fail only at System.loadLibrary on a device.
    println!("cargo:rustc-link-lib=static=c++abi");
    println!("cargo:rustc-link-lib=static=unwind");
    println!("cargo:rustc-link-lib=log");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rerun-if-env-changed=MOCIKA_XOP_ROOT");
    println!(
        "cargo:rerun-if-changed={}",
        manifest.join("src/xop_pvm2_bridge.cpp").display()
    );
    for source in &sources {
        rerun(&cpp.join(source));
    }
    rerun(&cpp.join("common/runtime_state.h"));
    rerun(&cpp.join("codeitem/multi_dex_code.h"));
    rerun(&cpp.join("crypto/aes.h"));
    rerun(&cpp.join("vm/pvm2_format.h"));
    rerun(&cpp.join("vm/pvm2_interp.h"));
}

fn rerun(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}
