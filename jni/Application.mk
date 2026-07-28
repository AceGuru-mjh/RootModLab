# Build both 32-bit and 64-bit ARM so the module works on all phones.
APP_ABI      := arm64-v8a armeabi-v7a
APP_PLATFORM := android-24
APP_STL      := c++_static
APP_PIE      := true
APP_OPTIM    := release
