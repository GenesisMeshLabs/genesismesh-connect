// Appended only to the isolated generated qualification project by its init script.
val ownerRepository = providers.gradleProperty("ownerRepository").orNull?.let { file(it).canonicalFile }
    ?: rootProject.projectDir.resolve("../../../../..").canonicalFile
val ownerWheelhouse = file(providers.gradleProperty("runtimeWheelhouse").get())
val ownerRequirements = file(providers.gradleProperty("runtimeRequirements").get())
require(ownerWheelhouse.isDirectory && ownerRequirements.isFile)
require(gradle.startParameter.taskNames.none { it.contains("release", ignoreCase = true) }) {
    "The embedded owner bridge is a disabled debug qualification build only."
}

val ownerPython = tasks.register<Sync>("prepareConnectOwnerPython") {
    from(ownerRepository.resolve("apps/connect/authority/embedded")) { include("*.py") }
    from(ownerRepository.resolve("apps/connect/authority")) {
        include("owner.py", "protection.py", "core_release.py", "core-requirements.txt")
    }
    from(ownerRepository.resolve("apps/connect/native/android/python")) { include("android_connect_owner.py") }
    into(layout.buildDirectory.dir("generated/connect-owner-python"))
}

// Tauri's pinned AGP 9 template uses its compatibility DSL. BaseExtension keeps
// the source-set type correct for both the application and build-only library.
val ownerSources = extensions.getByType(com.android.build.gradle.BaseExtension::class.java)
    .sourceSets.getByName("main")
ownerSources.java.srcDir(ownerRepository.resolve("apps/connect/native/android/src/main/java"))
ownerSources.java.srcDir(ownerRepository.resolve("apps/connect/native/android/bridge"))

chaquopy {
    sourceSets.getByName("main").srcDir(layout.buildDirectory.dir("generated/connect-owner-python"))
    defaultConfig {
        version = "3.13"
        buildPython(providers.gradleProperty("ownerBuildPython").getOrElse("python"))
        pip {
            options("--no-index", "--find-links", ownerWheelhouse.absolutePath, "--require-hashes", "--only-binary=:all:")
            install("-r", ownerRequirements.absolutePath)
        }
    }
}

tasks.configureEach {
    if (name.endsWith("PythonSources") || name == "preBuild") dependsOn(ownerPython)
}

// Chaquopy has Python 3.13 for arm64-v8a and x86_64 only. The generated Rust plugin
// also declares 32-bit ABI flavors; this app never builds them, so leave them out.
plugins.withId("com.android.application") {
    extensions.configure<com.android.build.api.variant.ApplicationAndroidComponentsExtension> {
        beforeVariants { variant ->
            if (variant.flavorName == "arm" || variant.flavorName == "x86") variant.enable = false
        }
    }
}

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.3")
}
