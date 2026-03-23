define Build/append-en8811h-firmware
  $(STAGING_DIR_HOST)/bin/fiptool update  \
    --blob uuid=$$($(STAGING_DIR_HOST)/bin/uuidgen -n @dns --md5 --name en8811h.bin),file=$(STAGING_DIR_IMAGE)/EthMD32.bin \
    $(STAGING_DIR_IMAGE)/an7581_$1-bl31-u-boot.fip
endef

define Build/append-as21x1x-firmware
  $(STAGING_DIR_HOST)/bin/fiptool update \
    --blob uuid=$$($(STAGING_DIR_HOST)/bin/uuidgen -n @dns --md5 --name as21xxx.bin),file=$(STAGING_DIR_ROOT)/lib/firmware/as21x1x_fw.bin \
    $(STAGING_DIR_IMAGE)/an7581_$1-bl31-u-boot.fip
endef

define Build/an7581-emmc-bl2-bl31-uboot
  head -c $$((0x800)) /dev/zero > $@
  cat $(STAGING_DIR_IMAGE)/an7581_$1-bl2.fip >> $@
  dd if=$(STAGING_DIR_IMAGE)/an7581_$1-bl31-u-boot.fip of=$@ bs=1 seek=$$((0x20000)) conv=notrunc
endef

define Build/an7581-preloader
  cat $(STAGING_DIR_IMAGE)/an7581_$1-bl2.fip >> $@
endef

define Build/an7581-bl31-uboot
  cat $(STAGING_DIR_IMAGE)/an7581_$1-bl31-u-boot.fip >> $@
endef

define Device/FitImageLzma
	KERNEL_SUFFIX := -uImage.itb
	KERNEL = kernel-bin | lzma | fit lzma $$(KDIR)/image-$$(DEVICE_DTS).dtb
	KERNEL_NAME := Image
endef

define Device/airoha_an7581-evb
  $(call Device/FitImageLzma)
  DEVICE_VENDOR := Airoha
  DEVICE_MODEL := AN7581 Evaluation Board (SNAND)
  DEVICE_PACKAGES := kmod-leds-pwm kmod-i2c-an7581 kmod-pwm-airoha kmod-sound-soc-an7581-wm8960 kmod-sound-an7581-pcm kmod-input-gpio-keys-polled
  DEVICE_DTS := an7581-evb
  DEVICE_DTS_CONFIG := config@1
  IMAGE/sysupgrade.bin := append-kernel | pad-to 128k | append-rootfs | pad-rootfs | append-metadata
  ARTIFACT/preloader.bin := an7581-preloader rfb
  ARTIFACT/bl31-uboot.fip := an7581-bl31-uboot rfb
  ARTIFACTS := preloader.bin bl31-uboot.fip
endef
TARGET_DEVICES += airoha_an7581-evb

define Device/airoha_an7581-evb-an8811
  $(call Device/airoha_an7581-evb)
  DEVICE_MODEL := AN7581 Evaluation Board (SNAND + AN8811)
  DEVICE_DTS := an7581-evb-an8811
endef
TARGET_DEVICES += airoha_an7581-evb-an8811

define Device/airoha_an7581-evb-emmc
  DEVICE_VENDOR := Airoha
  DEVICE_MODEL := AN7581 Evaluation Board (EMMC)
  DEVICE_DTS := an7581-evb-emmc
  DEVICE_PACKAGES := aeonsemi-as21xxx-firmware airoha-en8811h-firmware kmod-mt7996-firmware kmod-i2c-an7581 kmod-sound-soc-an7581-wm8960 kmod-sound-an7581-pcm
  ARTIFACT/preloader.bin := an7581-preloader rfb
  ARTIFACT/bl31-uboot.fip := append-as21x1x-firmware rfb | append-en8811h-firmware rfb | an7581-bl31-uboot rfb
  ARTIFACTS := preloader.bin bl31-uboot.fip
endef
TARGET_DEVICES += airoha_an7581-evb-emmc

define Device/airoha_an7581-evb-emmc-kite
  DEVICE_VENDOR := Airoha
  DEVICE_MODEL := AN7581 Evaluation Board (EMMC + KITE)
  DEVICE_DTS := an7581-evb-emmc-kite
  DEVICE_PACKAGES := aeonsemi-as21xxx-firmware airoha-en8811h-firmware kmod-mt7992-firmware kmod-i2c-an7581 kmod-sound-soc-an7581-wm8960 kmod-sound-an7581-pcm
  ARTIFACT/preloader.bin := an7581-preloader rfb
  ARTIFACT/bl31-uboot.fip := append-as21x1x-firmware rfb | append-en8811h-firmware rfb | an7581-bl31-uboot rfb
  ARTIFACTS := preloader.bin bl31-uboot.fip
endef
TARGET_DEVICES += airoha_an7581-evb-emmc-kite

define Device/nokia_valyrian
  DEVICE_VENDOR := Nokia
  DEVICE_MODEL := Valyrian
  DEVICE_DTS := an7581-nokia-valyrian
  DEVICE_PACKAGES := kmod-i2c-an7581 kmod-sfp kmod-phy-aeonsemi-as21xxx
  ARTIFACT/preloader.bin := an7581-preloader nokia_valyrian
  ARTIFACT/bl31-uboot.fip := append-as21x1x-firmware rfb | an7581-bl31-uboot nokia_valyrian
  ARTIFACTS := preloader.bin bl31-uboot.fip
endef
TARGET_DEVICES += nokia_valyrian
