plugins {
    id("com.android.dynamic-feature")
}

android {
    namespace = "dev.mocika.shield.featurefixture.conditional"
    compileSdk = 35
    ndkVersion = System.getenv("MOCIKA_NATIVE_VMP_NDK_VERSION") ?: "29.0.14206865"

    defaultConfig {
        minSdk = 21
        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"
                val vmpRoot = System.getenv("MOCIKA_NATIVE_VMP_ROOT")
                val vmpPlugin = System.getenv("MOCIKA_NATIVE_VMP_PLUGIN")
                val llvmOpt = System.getenv("MOCIKA_NATIVE_VMP_OPT")
                if (vmpRoot != null && vmpPlugin != null && llvmOpt != null) {
                    arguments += listOf(
                        "-DMOCIKA_NATIVE_VMP_ROOT=$vmpRoot",
                        "-DMOCIKA_NATIVE_VMP_PLUGIN=$vmpPlugin",
                        "-DMOCIKA_NATIVE_VMP_OPT=$llvmOpt",
                    )
                }
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
}

dependencies {
    implementation(project(":app"))
}
