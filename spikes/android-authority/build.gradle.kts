plugins {
    id("com.android.application") version "9.3.1"
    id("com.chaquo.python") version "17.2.0"
}

val repository = rootDir.resolve("../..").canonicalFile
val pin = repository.resolve("apps/connect/authority/core-requirements.txt").readLines()
    .map { it.substringBefore("#").trim() }.filter { it.isNotEmpty() }.single()
require(pin.startsWith("genesis-mesh=="))
val coreVersion = pin.substringAfter("==")
val wheelhouse = file(providers.gradleProperty("runtimeWheelhouse").get())
val requirements = file(providers.gradleProperty("runtimeRequirements").get())

android {
    namespace = "org.genesismesh.connect.authoritycheck"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    defaultConfig {
        applicationId = "org.genesismesh.connect.authoritycheck"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "engine-check"
        ndk { abiFilters += "arm64-v8a" }
        buildConfigField("String", "CORE_VERSION", "\"$coreVersion\"")
        buildConfigField("String", "SOURCE_COMMIT", "\"${System.getenv("GITHUB_SHA") ?: "local"}\"")
    }
    buildFeatures { buildConfig = true }
    sourceSets.getByName("main").res.srcDir(layout.buildDirectory.dir("generated/brand").get().asFile)
}

val prepareBrand = tasks.register<Copy>("prepareBrand") {
    from(repository.resolve("apps/connect/src-tauri/icons/icon.png"))
    into(layout.buildDirectory.dir("generated/brand/drawable"))
    rename { "genesis_mesh.png" }
}
tasks.named("preBuild") { dependsOn(prepareBrand) }

chaquopy {
    defaultConfig {
        version = "3.13"
        buildPython("python")
        pip {
            options("--no-index", "--find-links", wheelhouse.absolutePath, "--require-hashes", "--only-binary=:all:")
            install("-r", requirements.absolutePath)
        }
    }
}
