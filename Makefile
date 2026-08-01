ARCHS = arm64
TARGET = iphone:clang:15.0:15.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = JQTYPacketLog
JQTYPacketLog_FILES = Tweak.xm
JQTYPacketLog_CFLAGS = -fobjc-arc -Wno-deprecated-declarations

include $(THEOS_MAKE_PATH)/tweak.mk

after-package::
	cp .theos/obj/debug/arm64/JQTYPacketLog.dylib layout/Library/MobileSubstrate/DynamicLibraries/
	cp jqty.plist layout/Library/MobileSubstrate/DynamicLibraries/
	rm -rf packages
	mkdir -p packages
	dpkg-deb -Zgzip -b layout packages/com.jqty.packetlog_1.0_iphoneos-arm.deb
