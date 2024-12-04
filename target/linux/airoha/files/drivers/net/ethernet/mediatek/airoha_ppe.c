// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024 AIROHA Inc
 * Author: Lorenzo Bianconi <lorenzo@kernel.org>
 */

#include <linux/firmware.h>
#include <linux/of_reserved_mem.h>

#include "airoha_eth.h"

#define NPU_EN7581_NUM_CORES			8
#define NPU_EN7581_FIRMWARE_DATA		"airoha/en7581_npu_data.bin"
#define NPU_EN7581_FIRMWARE_RV32		"airoha/en7581_npu_rv32.bin"
#define NPU_EN7581_FIRMWARE_RV32_MAX_SIZE	0x200000
#define NPU_EN7581_FIRMWARE_DATA_MAX_SIZE	0x10000

#define REG_NPU_LOCAL_SRAM		0x0

#define NPU_CLUSTER_BASE_ADDR		0x306000
#define REG_CR_BOOT_TRIGGER		(NPU_CLUSTER_BASE_ADDR + 0x000)
#define REG_CR_BOOT_CONFIG		(NPU_CLUSTER_BASE_ADDR + 0x004)
#define REG_CR_BOOT_BASE(_n)		(NPU_CLUSTER_BASE_ADDR + 0x020 + ((_n) << 2))

#define NPU_MBOX_BASE_ADDR		0x30c000
#define REG_CR_MBOX_INT_STATUS		(NPU_MBOX_BASE_ADDR + 0x000)
#define REG_CR_MBOX_INT_MASK(_n)	(NPU_MBOX_BASE_ADDR + 0x004 + ((_n) << 2))
#define REG_CR_MBQ_CTRL(_n)		(NPU_MBOX_BASE_ADDR + 0x030 + ((_n) << 2))
#define REG_CR_NPU_MIB(_n)		(NPU_MBOX_BASE_ADDR + 0x140 + ((_n) << 2))

static void airoha_npu_wr(struct airoha_npu *npu, u32 reg, u32 val)
{
	writel(val, npu->base + reg);
}

static int airoha_npu_run_firmware(struct airoha_npu *npu, struct reserved_mem *rmem)
{
	struct device *dev = &npu->pdev->dev;
	const struct firmware *fw;
	void __iomem *addr;
	int ret;

	ret = request_firmware(&fw, NPU_EN7581_FIRMWARE_RV32, dev);
	if (ret)
		return ret;

	if (fw->size > NPU_EN7581_FIRMWARE_RV32_MAX_SIZE) {
		dev_err(dev, "%s: fw size too overlimit (%ld)\n",
			NPU_EN7581_FIRMWARE_RV32, fw->size);
		ret = -E2BIG;
		goto out;
	}

	addr = devm_ioremap(dev, rmem->base, rmem->size);
	memcpy_toio(addr, fw->data, fw->size);
	release_firmware(fw);

	ret = request_firmware(&fw, NPU_EN7581_FIRMWARE_DATA, dev);
	if (ret)
		return ret;

	if (fw->size > NPU_EN7581_FIRMWARE_DATA_MAX_SIZE) {
		dev_err(dev, "%s: fw size too overlimit (%ld)\n",
			NPU_EN7581_FIRMWARE_DATA, fw->size);
		ret = -E2BIG;
		goto out;
	}

	memcpy_toio(npu->base + REG_NPU_LOCAL_SRAM, fw->data, fw->size);
out:
	release_firmware(fw);

	return ret;
}

static int airoha_npu_init(struct airoha_npu *npu)
{
	struct reserved_mem *rmem;
	struct device_node *np;
	int i, err;

	npu->base = devm_platform_ioremap_resource(npu->pdev, 0);
	if (IS_ERR(npu->base))
		return PTR_ERR(npu->base);

	np = of_parse_phandle(npu->np, "memory-region", 0);
	if (!np)
		return -ENODEV;

	rmem = of_reserved_mem_lookup(np);
	of_node_put(np);

	err = airoha_npu_run_firmware(npu, rmem);
	if (err)
		return err;

	airoha_npu_wr(npu, REG_CR_NPU_MIB(10),
		      rmem->base + NPU_EN7581_FIRMWARE_RV32_MAX_SIZE);
	airoha_npu_wr(npu, REG_CR_NPU_MIB(11), 0);
	airoha_npu_wr(npu, REG_CR_NPU_MIB(12), 0);
	airoha_npu_wr(npu, REG_CR_NPU_MIB(21), 0);
	msleep(100);

	/* setting booting address */
	for (i = 0; i < NPU_EN7581_NUM_CORES; i++)
		airoha_npu_wr(npu, REG_CR_BOOT_BASE(i), rmem->base);
	usleep_range(1000, 2000);

	/* enable NPU cores */
	airoha_npu_wr(npu, REG_CR_BOOT_CONFIG,
		     GENMASK(NPU_EN7581_NUM_CORES - 1, 0));
	airoha_npu_wr(npu, REG_CR_BOOT_TRIGGER, 0x1);
	msleep(100);

	return 0;
}

int airoha_ppe_init(struct airoha_eth *eth)
{
	struct airoha_npu *npu;
	int err = -ENODEV;

	npu = devm_kzalloc(eth->dev, sizeof(*npu), GFP_KERNEL);
	if(!npu)
		return -ENOMEM;

	npu->np = of_parse_phandle(eth->dev->of_node, "airoha,npu", 0);
	if (!npu->np)
		return -ENODEV;

	npu->pdev = of_find_device_by_node(npu->np);
	if (!npu->pdev)
		goto error_of_node_put;

	get_device(&npu->pdev->dev);
	eth->npu = npu;

	err = airoha_npu_init(npu);
	if (err)
		goto error_put_dev;

	return 0;

error_put_dev:
	put_device(&npu->pdev->dev);
error_of_node_put:
	of_node_put(npu->np);

	return err;
}

void airoha_ppe_deinit(struct airoha_eth *eth)
{
	struct airoha_npu *npu = eth->npu;

	put_device(&npu->pdev->dev);
	of_node_put(npu->np);
}
