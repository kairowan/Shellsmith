import org.gradle.api.tasks.testing.Test

plugins {
    alias(libs.plugins.android.library)
}

val runtimeProfileEnabled = providers.environmentVariable("MOCIKA_RUNTIME_PROFILE")
    .orNull == "1"
val legacyByteArrayEnabled = providers.environmentVariable("MOCIKA_LEGACY_BYTE_ARRAY")
    .orNull == "1"
val byosRuntime = providers.environmentVariable("MOCIKA_BYOS_RUNTIME").orNull == "1"
val byosPlay = byosRuntime && providers.environmentVariable("MOCIKA_BYOS_PLAY_INTEGRITY").orNull == "1"
if (byosRuntime) layout.buildDirectory.set(file(if (byosPlay) "build-byos-play" else "build-byos"))
// 原生库启动期完整性校验：Release 默认开启，Debug 默认关闭；显式设置环境变量
// 可覆盖该默认值（1 开启，0 关闭）。校验失败会直接拒绝启动。
val nativeSelfCheckOverride = providers.environmentVariable("MOCIKA_NATIVE_SELF_CHECK").orNull
val nativeSelfCheckDebugEnabled = nativeSelfCheckOverride == "1"
val nativeSelfCheckReleaseEnabled = nativeSelfCheckOverride != "0"
// CI 默认固定版本；本机验证可通过 MOCIKA_NDK_VERSION 选择已安装的兼容 NDK。
val ndkVersionPinned = System.getenv("MOCIKA_NDK_VERSION") ?: "29.0.14206865"

android {
    namespace = "dev.mocika.shield.stub"
    compileSdk = 35
    ndkVersion = ndkVersionPinned

    defaultConfig {
        // 保留 API 19～20 的 Dalvik 分支；正式兼容资源仍使用独立的 r25c Native 库。
        minSdk = if (byosPlay) 29 else if (byosRuntime) 26 else 19

        testInstrumentationRunner = if (byosRuntime && !byosPlay) "dev.mocika.shield.loader.ByosDeviceContractTest" else "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
        }

        buildConfigField("boolean", "DEBUG_LOGS", "true")
        buildConfigField("boolean", "RUNTIME_PROFILE", runtimeProfileEnabled.toString())
        buildConfigField("boolean", "LEGACY_BYTE_ARRAY", legacyByteArrayEnabled.toString())
        buildConfigField("boolean", "NATIVE_SELF_CHECK", nativeSelfCheckDebugEnabled.toString())
    }

    buildTypes {
        release {
            // BYOS 与其依赖在构建脚本中一起混淆，避免把 Google 类留给宿主解析。
            isMinifyEnabled = !byosRuntime
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            buildConfigField("boolean", "DEBUG_LOGS", "false")
            buildConfigField("boolean", "NATIVE_SELF_CHECK", nativeSelfCheckReleaseEnabled.toString())
        }
        debug {
            buildConfigField("boolean", "DEBUG_LOGS", "true")
            buildConfigField("boolean", "NATIVE_SELF_CHECK", nativeSelfCheckDebugEnabled.toString())
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    testOptions {
        targetSdk = 35
    }

    lint {
        targetSdk = 35
    }

    buildFeatures {
        buildConfig = true
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("build/jniLibs")
            java.srcDir(if (byosRuntime) "src/byos/java" else "src/offline/java")
            if (byosRuntime) java.srcDir(if (byosPlay) "src/byosPlay/java" else "src/byosDevice/java")
        }
        if (byosRuntime) getByName("test").java.srcDir("src/byosTest/java")
        if (byosRuntime && !byosPlay) getByName("androidTest") {
            java.srcDir("src/byosDeviceTest/java")
            manifest.srcFile("src/byosDeviceTest/AndroidManifest.xml")
        }
    }
}

val buildRustLibs by tasks.registering(Exec::class) {
    group = "build"
    description = "编译 Rust Native 库"

    workingDir = file("src/main/rust")
    if (System.getProperty("os.name").lowercase().contains("windows")) {
        commandLine("cmd", "/c", "build.bat")
    } else {
        commandLine("bash", "./build.sh")
    }

    val ndkRoot = System.getenv("ANDROID_HOME")
        ?.let { "$it/ndk/$ndkVersionPinned" }
        ?.takeIf { file(it).isDirectory }
        ?: System.getenv("ANDROID_NDK_ROOT")
        ?: System.getenv("NDK_HOME")
        ?: error("未设置 ANDROID_NDK_ROOT、NDK_HOME 或 ANDROID_HOME，无法定位 NDK")
    environment("ANDROID_NDK_ROOT", ndkRoot)
}

tasks.named("preBuild") {
    dependsOn(buildRustLibs)
}

dependencies {
    if (byosPlay) implementation("com.google.android.play:integrity:1.6.0")
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.junit)
}

// 只导出已经由 Gradle 解析的运行时依赖，不额外下载或修改宿主工程。
tasks.register("exportByosDependencies") {
    doLast {
        check(byosRuntime)
        val destination = layout.buildDirectory.dir("byos-dependencies").get().asFile
        destination.deleteRecursively()
        destination.mkdirs()
        configurations.getByName("releaseRuntimeClasspath").files.forEachIndexed { index, artifact ->
            if (artifact.extension == "aar") {
                copy { from(zipTree(artifact)); include("classes.jar", "proguard.txt"); into(File(destination, index.toString())) }
            } else if (artifact.extension == "jar") {
                artifact.copyTo(File(destination, "$index.jar"))
            }
        }
    }
}

// Release AAR 的 runtime jar 是 R8 裁剪后的发布入口，内部类会被重命名或移除；
// Release 单测需要原始类验证实现细节，测试类路径优先使用编译产物，不改变发布包。
tasks.withType<Test>().configureEach {
    if (name == "testReleaseUnitTest") {
        val releaseClassesJar = layout.buildDirectory.file(
            "intermediates/compile_library_classes_jar/release/bundleLibCompileToJarRelease/classes.jar"
        )
        dependsOn("bundleLibCompileToJarRelease")
        doFirst {
            classpath = files(releaseClassesJar) + classpath
        }
    }
}
