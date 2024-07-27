// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023 AIROHA Inc.
 * Author: Ray Liu <ray.liu@airoha.com>
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/memblock.h>
#include <linux/module.h>

#include <linux/mtd/mtk_bmt.h>

#define AIROHA_ART_PARTNAME			"art"
#define AIROHA_ART_AUTO_OFFSET_REG		0xffffffff

static int airoha_partitions_parse(struct mtd_info *master,
				   const struct mtd_partition **pparts,
				   struct mtd_part_parser_data *data)
{
	struct device_node *mtd_node, *part_node, *pp;
	struct mtd_partition *parts;
	const char *partname;
	int np, total_np;

	mtd_node = mtd_get_of_node(master);
	if (!mtd_node)
		return 0;

	if (mtd_type_is_nand(master))
		mtk_bmt_attach(master);

	part_node = of_get_child_by_name(mtd_node, "partitions");
	if (!part_node)
		return 0;

	/* First count the subnodes */
	total_np = 0;
	for_each_child_of_node(part_node,  pp)
		total_np++;

	if (!total_np)
		return 0;

	parts = kcalloc(total_np, sizeof(*parts), GFP_KERNEL);
	if (!parts)
		return -ENOMEM;

	np = 0;
	for_each_child_of_node(part_node, pp) {
		const __be32 *reg;
		size_t offset, size;
		int len, a_cells, s_cells;

		partname = of_get_property(pp, "label", &len);
		/* Allow deprecated use of "name" instead of "label" */
		if (!partname)
			partname = of_get_property(pp, "name", &len);
		/* Fallback to node name per spec if all else fails: partname is always set */
		if (!partname)
			partname = pp->name;
		parts[np].name = partname;

		reg = of_get_property(pp, "reg", &len);
		if (!reg)
			goto fail;

		/* Fixed partition */
		a_cells = of_n_addr_cells(pp);
		s_cells = of_n_size_cells(pp);

		if ((len / 4) != (a_cells + s_cells)) {
			pr_debug("%s: airoha partition %pOF (%pOF) error parsing reg property.\n",
					master->name, pp, part_node);
			goto fail;
		}

		offset = of_read_number(reg, a_cells);
		size = of_read_number(reg + a_cells, s_cells);

		if (!strcmp(partname,AIROHA_ART_PARTNAME)) {
			/* ART partition must be the last partition */
			if (np + 1 != total_np) {
				pr_err("%s: airoha partition %pOF (%pOF) \"%s\" is not the last partition.\n",
				       master->name, pp, part_node, partname);
				goto fail;
			}

			/* With offset set to AUTO_OFFSET_RET, calculate the offset from the end of the flash */
			if (offset == AIROHA_ART_AUTO_OFFSET_REG) {
				struct property *prop;
				__be32 *new_reg;

				offset = master->size - size;
				/* Update the offset with the new calculate value in DT */
				prop = kzalloc(sizeof(*prop), GFP_KERNEL);
				if (!prop)
					goto fail;

				prop->name = "reg";
				prop->length = a_cells + s_cells;
				prop->value = kmemdup(reg, a_cells + s_cells, GFP_KERNEL);
				new_reg = prop->value;
				new_reg[a_cells - 1] = cpu_to_be32(offset);
				of_update_property(pp, prop);
			}
		}

		if ((offset + size) > master->size) {
			pr_err("%s: airoha partition %pOF (%pOF) \"%s\" extends past end of segment.\n",
			       master->name, pp, part_node, partname);
			goto fail;
		}

		parts[np].offset = offset;
		parts[np].size = size;
		parts[np].of_node = pp;

		if (of_get_property(pp, "read-only", &len))
			parts[np].mask_flags |= MTD_WRITEABLE;

		np++;
	}

	*pparts = parts;
	return np;

fail:
	pr_err("%s: error parsing airoha partition %pOF (%pOF)\n",
	       master->name, pp, part_node);
	of_node_put(pp);
	kfree(parts);
	return -EINVAL;
}

static const struct of_device_id parse_airoha_match_table[] = {
    { .compatible = "airoha,airoha-partitions" },
    {},
};
MODULE_DEVICE_TABLE(of, parse_airoha_match_table);

static struct mtd_part_parser airoha_parser = {
    .parse_fn = airoha_partitions_parse,
    .name = "airohapart",
    .of_match_table = parse_airoha_match_table,
};
module_mtd_part_parser(airoha_parser);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ray Liu <ray.liu@airoha.com>");
MODULE_DESCRIPTION("MTD partitioning for Airoha SoC");
