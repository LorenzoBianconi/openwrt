// SPDX-License-Identifier: GPL-2.0

#include <linux/cpufreq.h>
#include <linux/module.h>
#include <linux/arm-smccc.h>

#define AIROHA_SIP_AVS_HANDLE			0x82000301
#define AIROHA_AVS_OP_BASE			0xddddddd0
#define AIROHA_AVS_OP_MASK			GENMASK(1, 0)
#define AIROHA_AVS_OP_FREQ_DYN_ADJ		(AIROHA_AVS_OP_BASE | \
						 FIELD_PREP(AIROHA_AVS_OP_MASK, 0x1))
#define AIROHA_AVS_OP_GET_FREQ			(AIROHA_AVS_OP_BASE | \
						 FIELD_PREP(AIROHA_AVS_OP_MASK, 0x2))

struct airoha_cpufreq_priv {
	struct list_head list;

	cpumask_var_t cpus;
	struct device *cpu_dev;
	struct cpufreq_frequency_table *freq_table;
};

static LIST_HEAD(priv_list);

static unsigned int airoha_cpufreq_get(unsigned int cpu)
{
	struct arm_smccc_res res;

	arm_smccc_smc(AIROHA_SIP_AVS_HANDLE, AIROHA_AVS_OP_GET_FREQ,
		      0, 0, 0, 0, 0 ,0, &res);

	return (int) (res.a0 * 1000);
}

static int airoha_cpufreq_set_target(struct cpufreq_policy *policy, unsigned int index)
{
	struct arm_smccc_res res;

	arm_smccc_smc(AIROHA_SIP_AVS_HANDLE, AIROHA_AVS_OP_FREQ_DYN_ADJ,
		      0, index, 0, 0, 0 ,0, &res);

	return 0;
}


static struct airoha_cpufreq_priv *airoha_cpufreq_find_data(int cpu)
{
	struct airoha_cpufreq_priv *priv;

	list_for_each_entry(priv, &priv_list, list) {
		if (cpumask_test_cpu(cpu, priv->cpus))
			return priv;
	}

	return NULL;
}

static int airoha_cpufreq_init(struct cpufreq_policy *policy)
{
	struct airoha_cpufreq_priv *priv;
	struct device *cpu_dev;

	priv = airoha_cpufreq_find_data(policy->cpu);
	if (!priv)
		return -ENODEV;

	cpu_dev = priv->cpu_dev;
	cpumask_copy(policy->cpus, priv->cpus);
	policy->driver_data = priv;
	policy->freq_table = priv->freq_table;

	return 0;
}

static struct cpufreq_driver airoha_cpufreq_driver = {
	.flags		= CPUFREQ_NEED_INITIAL_FREQ_CHECK |
			  CPUFREQ_IS_COOLING_DEV,
	.verify		= cpufreq_generic_frequency_table_verify,
	.target_index	= airoha_cpufreq_set_target,
	.get		= airoha_cpufreq_get,
	.init		= airoha_cpufreq_init,
	.attr		= cpufreq_generic_attr,
	.name		= "airoha-cpufreq",
};

static int airoha_cpufreq_driver_init_cpu(int cpu)
{
	struct airoha_cpufreq_priv *priv;
	struct device *cpu_dev;
	int ret;

	cpu_dev = get_cpu_device(cpu);
	if (!cpu_dev)
		return -EPROBE_DEFER;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	if (!zalloc_cpumask_var(&priv->cpus, GFP_KERNEL))
		return -ENOMEM;

	cpumask_set_cpu(cpu, priv->cpus);
	priv->cpu_dev = cpu_dev;

	ret = dev_pm_opp_of_get_sharing_cpus(cpu_dev, priv->cpus);
	if (ret)
		goto err;

	ret = dev_pm_opp_of_cpumask_add_table(priv->cpus);
	if (ret)
		goto err;

	ret = dev_pm_opp_init_cpufreq_table(cpu_dev, &priv->freq_table);
	if (ret)
		goto err;

	list_add(&priv->list, &priv_list);

	return 0;

err:
	dev_pm_opp_of_cpumask_remove_table(priv->cpus);
	free_cpumask_var(priv->cpus);

	return ret;
}

static void airoha_cpufreq_release(void)
{
	struct airoha_cpufreq_priv *priv, *tmp;

	list_for_each_entry_safe(priv, tmp, &priv_list, list) {
		dev_pm_opp_free_cpufreq_table(priv->cpu_dev, &priv->freq_table);
		dev_pm_opp_of_cpumask_remove_table(priv->cpus);
		free_cpumask_var(priv->cpus);
		list_del(&priv->list);
		kfree(priv);
	}
}

static int __init airoha_cpufreq_driver_probe(void)
{
	int cpu, ret;

	if (!of_machine_is_compatible("airoha,en7581"))
		return -ENODEV;

	for_each_possible_cpu(cpu) {
		ret = airoha_cpufreq_driver_init_cpu(cpu);
		if (ret)
			goto err;
	}

	ret = cpufreq_register_driver(&airoha_cpufreq_driver);
	if (ret)
		goto err;

	return 0;

err:
	airoha_cpufreq_release();
	return ret;
}
module_init(airoha_cpufreq_driver_probe);

static void __exit airoha_cpufreq_driver_remove(void)
{
	cpufreq_unregister_driver(&airoha_cpufreq_driver);
	airoha_cpufreq_release();
}
module_exit(airoha_cpufreq_driver_remove);

MODULE_AUTHOR("Christian Marangi <ansuelsmth@gmail.com>");
MODULE_DESCRIPTION("CPUfreq driver for Airoha SoCs");
MODULE_LICENSE("GPL");
