#!/usr/bin/env bash
# build-rust-android.sh — cross-compile aivpn-android-core for all Android ABI targets
# and copy the resulting .so files into the app's jniLibs directory.
#
# Prerequisites:
#   cargo install cargo-ndk
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#
# Optional release signing via keystore.properties in aivpn-android/:
#   storeFile=/absolute/path/to/release.jks
#   storePassword=...
#   keyAlias=...
#   keyPassword=...
#
# Or via environment variables:
#   export AIVPN_UPLOAD_STORE_FILE=/absolute/path/to/release.jks
#   export AIVPN_UPLOAD_STORE_PASSWORD=...
#   export AIVPN_UPLOAD_KEY_ALIAS=...
#   export AIVPN_UPLOAD_KEY_PASSWORD=...
#
# Usage:
#   cd platforms/android
#   ./build-rust-android.sh            # debug build (default)
#   ./build-rust-android.sh release    # release build

set -euo pipefail

# Ensure ~/.cargo/bin is in PATH so cargo / rustup / cargo-ndk are found
# regardless of whether the caller sourced ~/.cargo/env beforehand.
if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    source "${HOME}/.cargo/env"
fi
export PATH="${HOME}/.cargo/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CRATE_DIR="${REPO_ROOT}/crates/aivpn-android-core"
JNI_LIBS_DIR="${SCRIPT_DIR}/app/src/main/jniLibs"
RELEASES_DIR="${REPO_ROOT}/releases"
APK_DST="${RELEASES_DIR}/aivpn-client.apk"

BUILD_TYPE="${1:-debug}"

pick_android_java_home() {
    if [[ -n "${AIVPN_ANDROID_JAVA_HOME:-}" ]]; then
        echo "${AIVPN_ANDROID_JAVA_HOME}"
        return 0
    fi

    if [[ -n "${JAVA_HOME:-}" ]]; then
        echo "${JAVA_HOME}"
        return 0
    fi

    if command -v /usr/libexec/java_home >/dev/null 2>&1; then
        for version in 21 17; do
            local candidate
            candidate="$(/usr/libexec/java_home -v "${version}" 2>/dev/null || true)"
            if [[ -n "${candidate}" && -x "${candidate}/bin/java" ]]; then
                echo "${candidate}"
                return 0
            fi
        done
    fi

    if command -v java >/dev/null 2>&1; then
        local java_bin
        java_bin="$(command -v java)"
        echo "$(cd "$(dirname "${java_bin}")/.." && pwd)"
        return 0
    fi

    return 1
}

if JAVA_HOME_SELECTED="$(pick_android_java_home)"; then
    export JAVA_HOME="${JAVA_HOME_SELECTED}"
    export PATH="${HOME}/.cargo/bin:${JAVA_HOME}/bin:${PATH}"
else
    echo "ERROR: Java runtime not found. Install JDK 17 or JDK 21 and retry."
    exit 1
fi

echo "==> Building aivpn-android-core [${BUILD_TYPE}]"
echo "     Java: ${JAVA_HOME}"

# Require Android NDK
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    # Common locations for NDK installed via Android Studio or command-line tools
    for candidate in \
        "${HOME}/Library/Android/sdk/ndk/latest" \
        "${HOME}/Library/Android/sdk/ndk/$(ls "${HOME}/Library/Android/sdk/ndk/" 2>/dev/null | sort -V | tail -1)" \
        "/usr/local/share/android-commandlinetools/ndk/latest" \
        "/opt/android-ndk"; do
        if [[ -d "${candidate}" ]]; then
            export ANDROID_NDK_HOME="${candidate}"
            break
        fi
    done
fi

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "ERROR: ANDROID_NDK_HOME is not set and could not be auto-detected."
    echo "       Install the Android NDK and export ANDROID_NDK_HOME."
    exit 1
fi
echo "     NDK: ${ANDROID_NDK_HOME}"

# Confirm cargo-ndk is installed
if ! command -v cargo-ndk &>/dev/null; then
    echo "ERROR: cargo-ndk not found.  Run: cargo install cargo-ndk"
    exit 1
fi

RELEASE_FLAG=""
if [[ "${BUILD_TYPE}" == "release" ]]; then
    RELEASE_FLAG="--release"
fi

TARGETS=(
    "arm64-v8a:aarch64-linux-android"
    "armeabi-v7a:armv7-linux-androideabi"
)

# Ensure stale x86_64 output from previous builds is not packaged into APK.
rm -rf "${JNI_LIBS_DIR}/x86_64"

for entry in "${TARGETS[@]}"; do
    ABI="${entry%%:*}"
    TARGET="${entry##*:}"
    echo "--> [${ABI}]  cargo ndk -t ${ABI}"

    (
        cd "${REPO_ROOT}"
        cargo ndk \
            -t "${ABI}" \
            -o "${JNI_LIBS_DIR}" \
            -- build -p aivpn-android-core \
            ${RELEASE_FLAG}
    )

    echo "    Written to ${JNI_LIBS_DIR}/${ABI}/libaivpn_core.so"
done

echo ""
echo "==> Done.  .so files in ${JNI_LIBS_DIR}:"
find "${JNI_LIBS_DIR}" -name "libaivpn_core.so" -exec ls -lh {} \;

echo ""
echo "==> Building Android APK and publishing to releases/..."
mkdir -p "${RELEASES_DIR}"
rm -f "${APK_DST}"

if [[ "${BUILD_TYPE}" == "release" ]]; then
    if [[ -f "${SCRIPT_DIR}/keystore.properties" ]]; then
        echo "     Release signing: using ${SCRIPT_DIR}/keystore.properties"
    elif [[ -n "${AIVPN_UPLOAD_STORE_FILE:-}" && -n "${AIVPN_UPLOAD_STORE_PASSWORD:-}" && -n "${AIVPN_UPLOAD_KEY_ALIAS:-}" && -n "${AIVPN_UPLOAD_KEY_PASSWORD:-}" ]]; then
        echo "     Release signing: custom keystore (${AIVPN_UPLOAD_KEY_ALIAS})"
    else
        echo "     Release signing: no custom keystore configured, Gradle will emit unsigned APK"
        if [[ "${AIVPN_ALLOW_DEBUG_APK:-0}" != "1" ]]; then
            echo "" >&2
            echo "ERROR: release build requested with no release signing configured." >&2
            echo "" >&2
            echo "  Without a keystore this script used to fall back to a DEBUG APK, and that" >&2
            echo "  build then shipped as the published release asset. A debug APK carries" >&2
            echo "  android:debuggable=\"true\" — anyone with adb access can attach to the VPN" >&2
            echo "  process and read session keys and the PSK out of its memory — and it is" >&2
            echo "  signed with the public Android debug key, so it proves nothing about who" >&2
            echo "  built it and cannot be upgraded to a properly signed build." >&2
            echo "" >&2
            echo "  Provide signing material via platforms/android/keystore.properties or the" >&2
            echo "  AIVPN_UPLOAD_STORE_FILE / _STORE_PASSWORD / _KEY_ALIAS / _KEY_PASSWORD" >&2
            echo "  environment variables (in CI: repository secrets)." >&2
            echo "" >&2
            echo "  For a local test build only, re-run with AIVPN_ALLOW_DEBUG_APK=1 — never" >&2
            echo "  publish the artifact it produces." >&2
            exit 1
        fi
        echo "     AIVPN_ALLOW_DEBUG_APK=1 — debug-signed fallback allowed (local testing only)"
    fi
fi

if [[ ! -x "${SCRIPT_DIR}/gradlew" ]]; then
    chmod +x "${SCRIPT_DIR}/gradlew" || true
fi

GRADLE_ARGS=(--no-daemon -Dkotlin.compiler.execution.strategy=in-process)

(
    cd "${SCRIPT_DIR}"
    ./gradlew --stop >/dev/null 2>&1 || true
)

if [[ "${BUILD_TYPE}" == "release" ]]; then
    (
        cd "${SCRIPT_DIR}"
        ./gradlew "${GRADLE_ARGS[@]}" app:assembleRelease
    )

    RELEASE_APK_SIGNED="${SCRIPT_DIR}/app/build/outputs/apk/release/app-universal-release.apk"
    RELEASE_APK_UNSIGNED="${SCRIPT_DIR}/app/build/outputs/apk/release/app-universal-release-unsigned.apk"
    RELEASE_APK_SIGNED_LOCAL="${SCRIPT_DIR}/app/build/outputs/apk/release/app-universal-release-signed.apk"

    if [[ -f "${RELEASE_APK_SIGNED}" ]]; then
        cp -f "${RELEASE_APK_SIGNED}" "${APK_DST}"
        echo "  Copied signed release APK -> ${APK_DST}"
    elif [[ -f "${RELEASE_APK_UNSIGNED}" ]]; then
        echo "  release APK is unsigned. Attempting to sign with debug keystore..."
        # Use apksigner (not jarsigner) — targetSdk 34+ requires APK Signature Scheme v2;
        # jarsigner produces v1-only signatures which Android rejects as invalid.
        if command -v apksigner >/dev/null 2>&1 && [[ -f "${HOME}/.android/debug.keystore" ]]; then
            apksigner sign \
                --ks "${HOME}/.android/debug.keystore" \
                --ks-pass pass:android \
                --key-pass pass:android \
                --ks-key-alias androiddebugkey \
                --out "${RELEASE_APK_SIGNED_LOCAL}" \
                "${RELEASE_APK_UNSIGNED}"

            if apksigner verify "${RELEASE_APK_SIGNED_LOCAL}" >/dev/null 2>&1; then
                cp -f "${RELEASE_APK_SIGNED_LOCAL}" "${APK_DST}"
                echo "  Signed release APK (v2/v3) with debug.keystore -> ${APK_DST}"
            else
                echo "  WARNING: apksigner verification failed. Falling back to debug APK..."
            fi
        else
            echo "  WARNING: apksigner/debug.keystore unavailable. Falling back to debug APK..."
        fi

        if [[ ! -f "${APK_DST}" || "$(shasum -a 256 "${APK_DST}" | awk '{print $1}')" == "$(shasum -a 256 "${RELEASE_APK_UNSIGNED}" | awk '{print $1}')" ]]; then
            if [[ "${AIVPN_ALLOW_DEBUG_APK:-0}" != "1" ]]; then
                echo "" >&2
                echo "ERROR: release signing did not produce a signed APK." >&2
                echo "  Refusing the debug-APK fallback: it is debuggable, so anyone with adb" >&2
                echo "  access could read session keys out of the VPN process. Fix the keystore" >&2
                echo "  configuration, or set AIVPN_ALLOW_DEBUG_APK=1 for a local test build." >&2
                exit 1
            fi
            echo "  Building signed debug APK as installable fallback..."
            (
                cd "${SCRIPT_DIR}"
                ./gradlew "${GRADLE_ARGS[@]}" app:assembleDebug
            )
            DEBUG_APK="${SCRIPT_DIR}/app/build/outputs/apk/debug/app-universal-debug.apk"
            if [[ -f "${DEBUG_APK}" ]]; then
                cp -f "${DEBUG_APK}" "${APK_DST}"
                echo "  Copied debug APK fallback -> ${APK_DST}"
            else
                echo "ERROR: debug fallback APK not found: ${DEBUG_APK}"
                exit 1
            fi
        fi
    else
        echo "ERROR: release APK not found in expected output paths."
        exit 1
    fi
else
    (
        cd "${SCRIPT_DIR}"
        ./gradlew "${GRADLE_ARGS[@]}" app:assembleDebug
    )
    DEBUG_APK="${SCRIPT_DIR}/app/build/outputs/apk/debug/app-universal-debug.apk"
    if [[ -f "${DEBUG_APK}" ]]; then
        cp -f "${DEBUG_APK}" "${APK_DST}"
        echo "  Copied debug APK -> ${APK_DST}"
    else
        echo "ERROR: debug APK not found: ${DEBUG_APK}"
        exit 1
    fi
fi

echo "==> Final artifact: ${APK_DST}"
ls -lh "${APK_DST}"
