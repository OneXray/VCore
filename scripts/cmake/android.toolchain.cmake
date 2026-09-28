# Let the NDK select C/C++/ASM compilers consistently across repeated configure
# calls. Passing a target clang wrapper as CMAKE_C_COMPILER makes the NDK replace
# it, which triggers CMake's cache reset on boring-sys's second configure.
set(ANDROID_ABI "$ENV{VCORE_CMAKE_ANDROID_ABI}")
set(ANDROID_PLATFORM "android-$ENV{VCORE_CMAKE_ANDROID_API}")
set(ANDROID_STL c++_shared)
include("$ENV{ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake")
