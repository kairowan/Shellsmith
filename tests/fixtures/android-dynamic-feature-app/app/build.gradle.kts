plugins {
    id("com.android.application")
}

android {
    namespace = "dev.mocika.shield.featurefixture"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.mocika.shield.featurefixture"
        minSdk = 21
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    dynamicFeatures += setOf(":feature", ":conditional_feature", ":ondemand_feature")
    assetPacks += setOf(":install_assets", ":fast_assets", ":ondemand_assets")

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
