import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("com.chaquo.python")
}

android {
    namespace = "org.genesismesh.connect.ownerqualification"
    compileSdk = 36
    defaultConfig {
        minSdk = 35
        ndk { abiFilters += "arm64-v8a" }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}
kotlin { compilerOptions { jvmTarget = JvmTarget.JVM_1_8 } }

dependencies {
    implementation(project(":tauri-android"))
    implementation("androidx.appcompat:appcompat:1.7.1")
    // Same version as the pinned Tauri Android library's public JSON-mapper API.
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.3")
}
