#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CORE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ANDROID_HOME=${ANDROID_HOME:-"$HOME/Library/Android/sdk"}
NDK_VERSION=${VCORE_ANDROID_NDK_VERSION:-28.2.13676358}
NDK_HOME=${ANDROID_NDK_HOME:-"$ANDROID_HOME/ndk/$NDK_VERSION"}
ANDROID_API=${VCORE_ANDROID_API:-24}
PROFILE=${VCORE_BUILD_PROFILE:-release}
FEATURES=${VCORE_FEATURES:-ffi,tun,inbound-http,outbound-vless}
TARGETS=${VCORE_ANDROID_TARGETS:-"aarch64-linux-android x86_64-linux-android"}
OUTPUT_DIR=${VCORE_ANDROID_OUTPUT_DIR:-"$CORE_DIR/dist/android"}
EXPECTED_IDENTITY='OneVCore/VCore;engine=rust;coreVersion=0.1.0;invokeApiVersion=5;configVersion=11'

case "$PROFILE" in
  release)
    PROFILE_FLAG=--release
    export CARGO_PROFILE_RELEASE_PANIC=unwind
    ;;
  debug)
    PROFILE_FLAG=
    ;;
  *)
    echo "unsupported VCORE_BUILD_PROFILE: $PROFILE" >&2
    exit 2
    ;;
esac

HOST_OS=$(uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH=$(uname -m)
TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$HOST_ARCH"
if [ ! -d "$TOOLCHAIN" ]; then
  case "$HOST_ARCH" in
    arm64) FALLBACK_ARCH=x86_64 ;;
    *) FALLBACK_ARCH=arm64 ;;
  esac
  TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_OS-$FALLBACK_ARCH"
fi
if [ ! -d "$TOOLCHAIN" ]; then
  echo "Android NDK toolchain not found under $NDK_HOME" >&2
  exit 3
fi

export ANDROID_NDK_HOME=$NDK_HOME
export ANDROID_NDK_ROOT=$NDK_HOME
export ANDROID_NDK=$NDK_HOME

build_target() {
  target=$1
  case "$target" in
    aarch64-linux-android)
      abi=arm64-v8a
      clang=aarch64-linux-android${ANDROID_API}-clang
      env_name=AARCH64_LINUX_ANDROID
      ;;
    x86_64-linux-android)
      abi=x86_64
      clang=x86_64-linux-android${ANDROID_API}-clang
      env_name=X86_64_LINUX_ANDROID
      ;;
    armv7-linux-androideabi)
      abi=armeabi-v7a
      clang=armv7a-linux-androideabi${ANDROID_API}-clang
      env_name=ARMV7_LINUX_ANDROIDEABI
      ;;
    *)
      echo "unsupported Android Rust target: $target" >&2
      exit 4
      ;;
  esac

  rustup target list --installed | grep -qx "$target" || {
    echo "Rust target is not installed: $target" >&2
    exit 5
  }
  linker="$TOOLCHAIN/bin/$clang"
  if [ ! -x "$linker" ]; then
    echo "Android linker not found: $linker" >&2
    exit 6
  fi

  target_env=$(printf '%s' "$target" | tr '-' '_')
  eval "export CC_${target_env}=\"$linker\""
  eval "export AR_${target_env}=\"$TOOLCHAIN/bin/llvm-ar\""
  eval "export CARGO_TARGET_${env_name}_LINKER=\"$linker\""
  eval "export CARGO_TARGET_${env_name}_AR=\"$TOOLCHAIN/bin/llvm-ar\""

  cargo build \
    --manifest-path "$CORE_DIR/Cargo.toml" \
    --locked \
    --target "$target" \
    ${PROFILE_FLAG:+$PROFILE_FLAG} \
    --no-default-features \
    --features "$FEATURES"

  built_library="$CORE_DIR/target/$target/$PROFILE/libvcore.so"
  if ! strings "$built_library" | grep -Fq "$EXPECTED_IDENTITY"; then
    echo "VCore Android artifact has a missing or incompatible Rust identity: $built_library" >&2
    exit 7
  fi

  mkdir -p "$OUTPUT_DIR/$abi"
  cp "$built_library" "$OUTPUT_DIR/$abi/libvcore.so"
}

for target in $TARGETS; do
  build_target "$target"
done

echo "$OUTPUT_DIR"
