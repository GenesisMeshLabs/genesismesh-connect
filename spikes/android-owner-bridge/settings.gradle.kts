pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
    plugins {
        id("com.android.library") version "9.3.1"
        id("org.jetbrains.kotlin.android") version "2.2.10"
        val pin = file("../android-authority/build.gradle.kts").readText()
        val version = Regex("id\\(\"com.chaquo.python\"\\) version \"([^\"]+)\"").find(pin)!!.groupValues[1]
        id("com.chaquo.python") version version
    }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
rootProject.name = "genesis-mesh-owner-bridge-build-only"
require(file("generated.gradle.kts").isFile) { "Run android:owner:init bridge-only before compiling this library" }
rootProject.buildFileName = "generated.gradle.kts"
val tauriDirectory = file(providers.gradleProperty("tauriAndroidDir").get()).canonicalFile
val expected = Regex("tauri = \\{ version = \"=([^\"]+)\"")
    .find(file("../../apps/connect/src-tauri/Cargo.toml").readText())!!.groupValues[1]
val actual = Regex("(?m)^version = \"([^\"]+)\"")
    .find(tauriDirectory.parentFile.parentFile.resolve("Cargo.toml").readText())!!.groupValues[1]
require(expected == actual) { "The bridge must compile against Connect's pinned Tauri SDK" }
include(":tauri-android")
project(":tauri-android").projectDir = tauriDirectory
