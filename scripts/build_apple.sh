#!/bin/sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CORE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${VCORE_APPLE_DIST_DIR:-"$CORE_DIR/dist/apple"}
WORK_DIR="$CORE_DIR/target/vcore-apple"
PROFILE=${VCORE_BUILD_PROFILE:-release}
FEATURES=${VCORE_FEATURES:-ffi,tun,inbound-http,outbound-vless}
IOS_MIN=${VCORE_IOS_DEPLOYMENT_TARGET:-13.0}
MACOS_MIN=${VCORE_MACOS_DEPLOYMENT_TARGET:-10.15}
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

export IPHONEOS_DEPLOYMENT_TARGET=$IOS_MIN
export MACOSX_DEPLOYMENT_TARGET=$MACOS_MIN

rm -rf "$WORK_DIR" "$DIST_DIR/LibVCore.xcframework"
mkdir -p "$WORK_DIR/ios-device" "$WORK_DIR/ios-simulator" "$WORK_DIR/macos" "$DIST_DIR"

build_target() {
  target=$1
  rustup target list --installed | grep -qx "$target" || {
    echo "Rust target is not installed: $target" >&2
    exit 3
  }
  cargo build \
    --manifest-path "$CORE_DIR/Cargo.toml" \
    --locked \
    --target "$target" \
    ${PROFILE_FLAG:+$PROFILE_FLAG} \
    --no-default-features \
    --features "$FEATURES"
}

build_target aarch64-apple-ios
build_target aarch64-apple-ios-sim
build_target x86_64-apple-ios
build_target aarch64-apple-darwin
build_target x86_64-apple-darwin

for library in \
  "$CORE_DIR/target/aarch64-apple-ios/$PROFILE/libvcore.a" \
  "$CORE_DIR/target/aarch64-apple-ios-sim/$PROFILE/libvcore.a" \
  "$CORE_DIR/target/x86_64-apple-ios/$PROFILE/libvcore.a" \
  "$CORE_DIR/target/aarch64-apple-darwin/$PROFILE/libvcore.a" \
  "$CORE_DIR/target/x86_64-apple-darwin/$PROFILE/libvcore.a"
do
  if ! strings "$library" | grep -Fq "$EXPECTED_IDENTITY"; then
    echo "VCore Apple artifact has a missing or incompatible Rust identity: $library" >&2
    exit 7
  fi
done

cp "$CORE_DIR/target/aarch64-apple-ios/$PROFILE/libvcore.a" \
  "$WORK_DIR/ios-device/libvcore.a"

xcrun lipo -create \
  "$CORE_DIR/target/aarch64-apple-ios-sim/$PROFILE/libvcore.a" \
  "$CORE_DIR/target/x86_64-apple-ios/$PROFILE/libvcore.a" \
  -output "$WORK_DIR/ios-simulator/libvcore.a"

xcrun lipo -create \
  "$CORE_DIR/target/aarch64-apple-darwin/$PROFILE/libvcore.a" \
  "$CORE_DIR/target/x86_64-apple-darwin/$PROFILE/libvcore.a" \
  -output "$WORK_DIR/macos/libvcore.a"

xcodebuild -create-xcframework \
  -library "$WORK_DIR/ios-device/libvcore.a" \
  -headers "$CORE_DIR/include" \
  -library "$WORK_DIR/ios-simulator/libvcore.a" \
  -headers "$CORE_DIR/include" \
  -library "$WORK_DIR/macos/libvcore.a" \
  -headers "$CORE_DIR/include" \
  -output "$DIST_DIR/LibVCore.xcframework"

echo "$DIST_DIR/LibVCore.xcframework"
