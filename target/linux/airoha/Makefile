include $(TOPDIR)/rules.mk

ARCH:=arm
BOARD:=airoha
BOARDNAME:=Airoha EN75xx
SUBTARGETS:=en7581 en7523
FEATURES:=dt squashfs nand ramdisk gpio source-only pwm

KERNEL_PATCHVER:=6.1
KERNEL_TESTING_PATCHVER:=6.6

include $(INCLUDE_DIR)/target.mk

DEFAULT_PACKAGES += \
	kmod-leds-gpio kmod-gpio-button-hotplug

$(eval $(call BuildTarget))
