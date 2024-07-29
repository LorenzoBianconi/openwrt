// SPDX-License-Identifier: GPL-2.0
/* FILE NAME:  mdio-arht.c
 * PURPOSE:
 *      Airoha MDIO bus Controller Driver
 * NOTES:
 *
 */

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_mdio.h>
#include <linux/phy.h>
#include <linux/platform_device.h>
#include <linux/sched.h>

#define AIROHA_PHY_IAC			0x701C
#define  AIROHA_PHY_ACS_ST		BIT(31)
#define  AIROHA_MDIO_REG_ADDR_MASK	(0x1f << 25)
#define  AIROHA_MDIO_PHY_ADDR_MASK	(0x1f << 20)
#define  AIROHA_MDIO_CMD_MASK		(0x3 << 18)
#define  AIROHA_MDIO_ST_MASK		(0x3 << 16)
#define  AIROHA_MDIO_RW_DATA_MASK	(0xffff)
#define  AIROHA_MDIO_REG_ADDR(x)	(((x) & 0x1f) << 25)
#define  AIROHA_MDIO_DEV_ADDR(x)	(((x) & 0x1f) << 25)
#define  AIROHA_MDIO_PHY_ADDR(x)	(((x) & 0x1f) << 20)
#define  AIROHA_MDIO_CMD(x)		(((x) & 0x3) << 18)
#define  AIROHA_MDIO_ST(x)		(((x) & 0x3) << 16)

enum airoha_phy_iac_cmd {
	AIROHA_MDIO_ADDR = 0,
	AIROHA_MDIO_WRITE = 1,
	AIROHA_MDIO_READ = 2,
	AIROHA_MDIO_READ_CL45 = 3,
};

/* MDIO_ST: MDIO start field */
enum airoha_mdio_st {
	AIROHA_MDIO_ST_CL45 = 0,
	AIROHA_MDIO_ST_CL22 = 1,
};

#define  AIROHA_MDIO_CL22_READ		(AIROHA_MDIO_ST(AIROHA_MDIO_ST_CL22) | \
					 AIROHA_MDIO_CMD(AIROHA_MDIO_READ))
#define  AIROHA_MDIO_CL22_WRITE		(AIROHA_MDIO_ST(AIROHA_MDIO_ST_CL22) | \
					 AIROHA_MDIO_CMD(AIROHA_MDIO_WRITE))
#define  AIROHA_MDIO_CL45_ADDR		(AIROHA_MDIO_ST(AIROHA_MDIO_ST_CL45) | \
					 AIROHA_MDIO_CMD(AIROHA_MDIO_ADDR))
#define  AIROHA_MDIO_CL45_READ		(AIROHA_MDIO_ST(AIROHA_MDIO_ST_CL45) | \
					 AIROHA_MDIO_CMD(AIROHA_MDIO_READ))
#define  AIROHA_MDIO_CL45_WRITE		(AIROHA_MDIO_ST(AIROHA_MDIO_ST_CL45) | \
					 AIROHA_MDIO_CMD(AIROHA_MDIO_WRITE))

struct airoha_mdio_priv {
	struct device *dev;
	void __iomem *regs;
	struct mutex mutex;
};

struct airoha_mdio_dummy_poll {
	struct airoha_mdio_priv *priv;
	u32 reg;
};

static u32 airoha_mdio_mii_read(struct airoha_mdio_priv *priv, u32 reg)
{
	return readl(priv->regs + reg);
}

static u32 airoha_mdio_read(struct airoha_mdio_dummy_poll *p)
{
	return airoha_mdio_mii_read(p->priv, p->reg);
}

static void airoha_mdio_mii_wirte(struct airoha_mdio_priv *priv, u32 reg,
				  u32 val)
{
	writel(val, priv->regs + reg);
}

static int airoha_mdio_read_c22(struct mii_bus *bus, int port, int regnum)
{
	struct airoha_mdio_priv *priv = bus->priv;
	struct airoha_mdio_dummy_poll p = {
		.priv = priv,
		.reg = AIROHA_PHY_IAC,
	};
	int ret;
	u32 val;

	mutex_lock(&priv->mutex);

	ret = readx_poll_timeout(airoha_mdio_read, &p, val,
				 !(val & AIROHA_PHY_ACS_ST), 20, 100000);
	if (ret < 0) {
		dev_err(priv->dev, "poll timeout\n");
		goto out;
	}

	val = AIROHA_MDIO_CL22_READ | AIROHA_MDIO_PHY_ADDR(port) |
	      AIROHA_MDIO_REG_ADDR(regnum);

	airoha_mdio_mii_wirte(priv, AIROHA_PHY_IAC, val | AIROHA_PHY_ACS_ST);

	ret = readx_poll_timeout(airoha_mdio_read, &p, val,
				 !(val & AIROHA_PHY_ACS_ST), 20, 100000);
	if (ret < 0) {
		dev_err(priv->dev, "poll timeout\n");
		goto out;
	}

	ret = val & AIROHA_MDIO_RW_DATA_MASK;
out:
	mutex_unlock(&priv->mutex);

	return ret;
}

static int airoha_mdio_write_c22(struct mii_bus *bus, int port,
				 int regnum, u16 data)
{	
	struct airoha_mdio_priv *priv = bus->priv;
	struct airoha_mdio_dummy_poll p = {
		.priv = priv,
		.reg = AIROHA_PHY_IAC,
	};
	int ret;
	u32 val;

	mutex_lock(&priv->mutex);

	ret = readx_poll_timeout(airoha_mdio_read, &p, val,
				 !(val & AIROHA_PHY_ACS_ST), 20, 100000);
	if (ret < 0) {
		dev_err(priv->dev, "poll timeout\n");
		goto out;
	}

	val = AIROHA_MDIO_CL22_WRITE | AIROHA_MDIO_PHY_ADDR(port) |
	      AIROHA_MDIO_REG_ADDR(regnum) | data;

	airoha_mdio_mii_wirte(priv, AIROHA_PHY_IAC, val | AIROHA_PHY_ACS_ST);

	ret = readx_poll_timeout(airoha_mdio_read, &p, val,
				 !(val & AIROHA_PHY_ACS_ST), 20, 100000);
	if (ret < 0) {
		dev_err(priv->dev, "poll timeout\n");
		goto out;
	}

out:
	mutex_unlock(&priv->mutex);

	return ret;
}

static int airoha_mdio_probe(struct platform_device *pdev)
{
	struct airoha_mdio_priv *priv;
	struct mii_bus *bus;
	int err;

	bus = devm_mdiobus_alloc_size(&pdev->dev, sizeof(*priv));
	if (!bus) {
		dev_err(&pdev->dev, "MDIO bus alloc failed\n");
		return -ENOMEM;
	}

	bus->name = KBUILD_MODNAME "-mii";
	bus->parent = &pdev->dev;
	bus->read = airoha_mdio_read_c22;
	bus->write = airoha_mdio_write_c22;

	priv = bus->priv;
	mutex_init(&priv->mutex);
	priv->dev = &pdev->dev;
	priv->regs = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->regs))
		return dev_err_probe(&pdev->dev, PTR_ERR(priv->regs),
				     "failed to map io regs\n");

	snprintf(bus->id, MII_BUS_ID_SIZE, KBUILD_MODNAME);
	platform_set_drvdata(pdev, bus);

	err = devm_of_mdiobus_register(&pdev->dev, bus, pdev->dev.of_node);
	if (err) {
		dev_err(&pdev->dev, "MDIO bus registration failed\n");
		platform_set_drvdata(pdev, NULL);
		return err;
	}

	return 0;
}

static const struct of_device_id airoha_mdio_of_match[] = {
	{ .compatible = "airoha,en7581-mdio", },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, airoha_mdio_of_match);

static struct platform_driver airoha_mdio_driver = {
	.driver = {
		.name = "airoha-mdio",
		.of_match_table = airoha_mdio_of_match,
	},
	.probe = airoha_mdio_probe,
};
module_platform_driver(airoha_mdio_driver);

MODULE_LICENSE("GPL v2");
