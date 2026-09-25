pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "mocika-shield-dynamic-feature"
include(
    ":app",
    ":feature",
    ":conditional_feature",
    ":ondemand_feature",
    ":install_assets",
    ":fast_assets",
    ":ondemand_assets",
)
