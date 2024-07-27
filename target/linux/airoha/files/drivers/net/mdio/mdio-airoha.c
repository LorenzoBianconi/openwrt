// SPDX-License-Identifier: GPL-2.0
/* FILE NAME:  mdio-arht.c
 * PURPOSE:
 *      Airoha MDIO bus Controller Driver
 * NOTES:
 *
 */

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/of_mdio.h>
#include <linux/phy.h>
#include <linux/platform_device.h>
#include <linux/sched.h>

static int airoha_mdio_read_c22(struct mii_bus *bus, int phy_id, int reg)
{
	return reg;
}

static int airoha_mdio_write_c22(struct mii_bus *bus, int phy_id,
				 int reg, u16 val)
{	
	return 0;
}

static int airoha_mdio_probe(struct platform_device *pdev)
{
	struct mii_bus *bus;
	int err;

	bus = devm_mdiobus_alloc(&pdev->dev);
	if (!bus) {
		dev_err(&pdev->dev, "MDIO bus alloc failed\n");
		return -ENOMEM;
	}

	//bus->priv = priv;
	bus->name = "airoha-mdio";
	bus->parent = &pdev->dev;
	bus->read = airoha_mdio_read_c22;
	bus->write = airoha_mdio_write_c22;
	snprintf(bus->id, MII_BUS_ID_SIZE, "%s-%d", pdev->name, pdev->id);
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
