define Device/airoha_en7581-evb
  DEVICE_VENDOR := Airoha
  DEVICE_MODEL := EN7581 Evaluation Board (SNAND)
  DEVICE_PACKAGES := kmod-leds-pwm kmod-i2c-en7581 kmod-pwm-airoha kmod-input-gpio-keys-polled
  DEVICE_DTS := en7581-evb
  DEVICE_DTS_DIR := ../dts
endef
TARGET_DEVICES += airoha_en7581-evb

define Device/airoha_en7581-evb-emmc
  DEVICE_VENDOR := Airoha
  DEVICE_MODEL := EN7581 Evaluation Board (EMMC)
  DEVICE_DTS := en7581-evb-emmc
  DEVICE_DTS_DIR := ../dts
  DEVICE_PACKAGES := kmod-i2c-en7581
endef
TARGET_DEVICES += airoha_en7581-evb-emmc
