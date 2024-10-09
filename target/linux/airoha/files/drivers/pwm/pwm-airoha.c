// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2022 Markus Gothe <markus.gothe@genexis.eu>
 *
 *  Limitations:
 *  - No disable bit, so a disabled PWM is simulated by setting duty_cycle to 0
 *  - Only 8 concurrent waveform generators are available for 8 combinations of
 *    duty_cycle and period. Waveform generators are shared between 16 GPIO
 *    slots and 17 SIPO GPIO slots/pins.
 *  - The gpio slots have a SoC specific mapping to the gpio pins.
 *  - Supports only normal polarity.
 *  - On configuration the currently running period is completed.
 */

#include <linux/bitfield.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/mfd/airoha-en7581-mfd.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pwm.h>
#include <linux/gpio.h>
#include <linux/bitops.h>
#include <asm/div64.h>

#define REG_SGPIO_LED_DATA		0x0024
#define SGPIO_LED_DATA_SHIFT_FLAG	BIT(31)
#define SGPIO_LED_DATA_DATA		GENMASK(16, 0)

#define REG_SGPIO_CLK_DIVR		0x0028
#define REG_SGPIO_CLK_DLY		0x002c

#define REG_SIPO_FLASH_MODE_CFG		0x0030
#define SERIAL_GPIO_FLASH_MODE		BIT(1)
#define SERIAL_GPIO_MODE		BIT(0)

#define REG_GPIO_FLASH_PRD_SET(_n)	(0x003c + ((_n) << 2))
#define GPIO_FLASH_PRD_MASK(_n)		GENMASK(15 + ((_n) << 4), ((_n) << 4))

#define REG_GPIO_FLASH_MAP(_n)		(0x004c + ((_n) << 2))
#define GPIO_FLASH_SETID_MASK(_n)	GENMASK(2 + ((_n) << 2), ((_n) << 2))
#define GPIO_FLASH_EN(_n)		BIT(3 + ((_n) << 2))

#define REG_SIPO_FLASH_MAP(_n)		(0x0054 + ((_n) << 2))

#define REG_CYCLE_CFG_VALUE(_n)		(0x0098 + ((_n) << 2))
#define WAVE_GEN_CYCLE_MASK(_n)		GENMASK(7 + ((_n) << 3), ((_n) << 3))

#define REG_FAN_EN			0x02BC
#define FAN_EN(_n)			BIT(1 << (_n))

struct airoha_pwm {
	struct pwm_chip chip;

	void __iomem *base;

	struct device_node *np;
	u64 initialized;

	struct {
		/* Bitmask of PWM channels using this bucket */
		u64 used;
		u64 period_ns;
		u64 duty_ns;
	} bucket[8];
};

/*
 * The first 16 GPIO pins, GPIO0-GPIO15, are mapped into 16 PWM channels, 0-15.
 * The SIPO GPIO pins are 17 pins which are mapped into 17 PWM channels, 16-32.
 * However, we've only got 8 concurrent waveform generators and can therefore
 * only use up to 8 different combinations of duty cycle and period at a time.
 */
#define PWM_NUM_GPIO	16
#define PWM_NUM_SIPO	17

/* The PWM hardware supports periods between 4 ms and 1 s */
#define PERIOD_MIN_NS	4 * NSEC_PER_MSEC
#define PERIOD_MAX_NS	2 * NSEC_PER_SEC
/* It is represented internally as 1/250 s between 1 and 250 */
#define PERIOD_MIN	1
#define PERIOD_MAX	250
/* Duty cycle is relative with 255 corresponding to 100% */
#define DUTY_FULL	255

#define DUTY_FACTOR_BIT_SCALE 10
#define DUTY_FACTOR_LIMIT (1 << (DUTY_FACTOR_BIT_SCALE-1))
#define ONEM_DIV_64KHZ	15625

static u32 airoha_pwm_rmw(struct airoha_pwm *pc, u32 addr, u32 mask, u32 val)
{
	val |= (readl(pc->base + addr) & ~mask);
	writel(val, pc->base + addr);

	return val;
}

#define airoha_pwm_set_bits(pc, addr, val)	\
	airoha_pwm_rmw((pc), (addr), (val), (val))

#define airoha_pwm_clear_bit(pc, addr, mask)	\
	airoha_pwm_rmw(pc, addr, mask, 0)

static int airoha_pwm_get_generator(struct airoha_pwm *pc, u64 duty_ns,
				    u64 period_ns)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pc->bucket); i++) {
		if (!pc->bucket[i].used)
			continue;

		if (duty_ns == pc->bucket[i].duty_ns &&
		    period_ns == pc->bucket[i].period_ns)
			return i;

		/*
		 * Unlike duty cycle zero, which can be handled by
		 * disabling PWM, a generator is needed for full duty
		 * cycle but it can be reused regardless of period
		 */
		if (duty_ns == DUTY_FULL && pc->bucket[i].duty_ns == DUTY_FULL)
			return i;
	}

	return -1;
}

static void airoha_pwm_release_bucket_config(struct airoha_pwm *pc,
					     unsigned int hwpwm)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pc->bucket); i++)
		pc->bucket[i].used &= ~BIT_ULL(hwpwm);
}

static int airoha_pwm_consume_generator(struct airoha_pwm *pc,
					u64 duty_ns, u64 period_ns,
					unsigned int hwpwm)
{
	int id = airoha_pwm_get_generator(pc, duty_ns, period_ns);

	if (id < 0) {
		int i;

		/* find an unused waveform generator */
		for (i = 0; i < ARRAY_SIZE(pc->bucket); i++) {
			if (!(pc->bucket[i].used & ~BIT_ULL(hwpwm))) {
				id = i;
				break;
			}
		}
	}

	if (id >= 0) {
		airoha_pwm_release_bucket_config(pc, hwpwm);
		pc->bucket[id].used |= BIT_ULL(hwpwm);
		pc->bucket[id].period_ns = period_ns;
		pc->bucket[id].duty_ns = duty_ns;
	}

	return id;
}

static int airoha_pwm_sipo_init(struct airoha_pwm *pc)
{
	u32 clk_divr_val = 3, sipo_clock_delay = 1;
	u32 val, sipo_clock_divisor = 32;

	if (!(pc->initialized >> PWM_NUM_GPIO))
		return 0;

	/* Select the right shift register chip */
	if (of_property_read_bool(pc->np, "hc74595"))
		airoha_pwm_set_bits(pc, REG_SIPO_FLASH_MODE_CFG,
				    SERIAL_GPIO_MODE);
	else
		airoha_pwm_clear_bit(pc, REG_SIPO_FLASH_MODE_CFG,
				     SERIAL_GPIO_MODE);

	if (!of_property_read_u32(pc->np, "sipo-clock-divisor",
				  &sipo_clock_divisor)) {
		switch (sipo_clock_divisor) {
		case 4:
			clk_divr_val = 0;
			break;
		case 8:
			clk_divr_val = 1;
			break;
		case 16:
			clk_divr_val = 2;
			break;
		case 32:
			clk_divr_val = 3;
			break;
		default:
			return -EINVAL;
		}
	}
	/* Configure shift register timings */
	writel(clk_divr_val, pc->base + REG_SGPIO_CLK_DIVR);

	of_property_read_u32(pc->np, "sipo-clock-delay", &sipo_clock_delay);
	if (sipo_clock_delay < 1 || sipo_clock_delay > sipo_clock_divisor / 2)
		return -EINVAL;

	/*
	 * The actual delay is sclkdly + 1 so subtract 1 from
	 * sipo-clock-delay to calculate the register value
	 */
	sipo_clock_delay--;
	writel(sipo_clock_delay, pc->base + REG_SGPIO_CLK_DLY);

	/*
	 * It it necessary to after muxing explicitly shift out all
	 * zeroes to initialize the shift register before enabling PWM
	 * mode because in PWM mode SIPO will not start shifting until
	 * it needs to output a non-zero value (bit 31 of led_data
	 * indicates shifting in progress and it must return to zero
	 * before led_data can be written or PWM mode can be set)
	 */
	if (readl_poll_timeout(pc->base + REG_SGPIO_LED_DATA, val,
			       !(val & SGPIO_LED_DATA_SHIFT_FLAG), 10,
			       200 * USEC_PER_MSEC))
		return -ETIMEDOUT;

	airoha_pwm_clear_bit(pc, REG_SGPIO_LED_DATA, SGPIO_LED_DATA_DATA);
	if (readl_poll_timeout(pc->base + REG_SGPIO_LED_DATA, val,
			       !(val & SGPIO_LED_DATA_SHIFT_FLAG), 10,
			       200 * USEC_PER_MSEC))
		return -ETIMEDOUT;

	/* Set SIPO in PWM mode */
	airoha_pwm_set_bits(pc, REG_SIPO_FLASH_MODE_CFG,
			    SERIAL_GPIO_FLASH_MODE);

	return 0;
}

static void airoha_pwm_calc_bucket_config(struct airoha_pwm *pc, int index,
					  u64 duty_ns, u64 period_ns)
{
	u32 duty, mask, val;
	u64 duty_factor_s, limit;
	int j, swap = 0;
	u8 high, low, tf;

	/* The pwm period is calculated as follows:
	 * period = time_factor * (low_duration + high_duration)
	 * time_factor = 1/clk
	 * clk can be 64kHz or 5MHz, in this driver only 64kHz is used
	 * the low 8 bits of REG_FAN_EN enables 5MHz clk, one bit per generator
	 * time_factor, low_duration and high_duration are 8-bit registers
	 *
	 * Because of the relation between registers it is possible to get
	 * the same pwm output from different register setups. The current
	 * code calculates a relation between the high and low high_duration
	 * register and the calculates a matching scale-factor.
	 *
	 * With periods near 2 seconds, duty cycles other then 50% are at
	 * the edge of what the hardware can support. Best resolution is
	 * available at 1 seconds periods.
	 */

	duty_factor_s = duty_ns / (period_ns >> DUTY_FACTOR_BIT_SCALE);

	/* Check if we need to swap the high/low registers */
	if (duty_factor_s > DUTY_FACTOR_LIMIT) {
		duty_factor_s = (period_ns-duty_ns) / (period_ns >> DUTY_FACTOR_BIT_SCALE);
		swap = 1;
	}

	/* Search for a high/low register value relation that matches
	 * the scaled duty factor */

	for (j = 0xFF ; j > 0 ; j--) {
		limit = ((j<<(2*DUTY_FACTOR_BIT_SCALE))/((j+0xFF)<<DUTY_FACTOR_BIT_SCALE));
		if (limit <= duty_factor_s)
			break;
	}

	if (swap) {
		high = 0xFF;
		low = j;
	} else {
		high = j;
		low = 0xFF;
	}
	tf = period_ns / ((low+high)*ONEM_DIV_64KHZ);

	/* Configure frequency divisor */
	mask = WAVE_GEN_CYCLE_MASK(index % 4);
	val = ((tf) << __ffs(mask)) & mask;
	airoha_pwm_rmw(pc, REG_CYCLE_CFG_VALUE(index / 4), mask, val);

	/* Configure duty cycle */
	duty = (low << 8) | high;
	mask = GPIO_FLASH_PRD_MASK(index % 2);
	val = (duty << __ffs(mask)) & mask;
	airoha_pwm_rmw(pc, REG_GPIO_FLASH_PRD_SET(index / 2), mask, val);
}

static void airoha_pwm_config_flash_map(struct airoha_pwm *pc,
					unsigned int hwpwm, int index)
{
	u32 addr, mask, val;

	if (hwpwm < PWM_NUM_GPIO) {
		addr = REG_GPIO_FLASH_MAP(hwpwm / 8);
	} else {
		addr = REG_SIPO_FLASH_MAP(hwpwm / 8);
		hwpwm -= PWM_NUM_GPIO;
	}

	if (index < 0) {
		/*
		 * Change of waveform takes effect immediately but
		 * disabling has some delay so to prevent glitching
		 * only the enable bit is touched when disabling
		 */
		airoha_pwm_clear_bit(pc, addr, GPIO_FLASH_EN(hwpwm % 8));
		return;
	}

	mask = GPIO_FLASH_SETID_MASK(hwpwm % 8);
	val = ((index & 7) << __ffs(mask)) & mask;
	airoha_pwm_rmw(pc, addr, mask, val);
	airoha_pwm_set_bits(pc, addr, GPIO_FLASH_EN(hwpwm % 8));
}

static int airoha_pwm_config(struct airoha_pwm *pc, struct pwm_device *pwm,
			     u64 duty_ns, u64 period_ns)
{
	int index = -1;

	index = airoha_pwm_consume_generator(pc, duty_ns, period_ns,
					     pwm->hwpwm);
	if (index < 0)
		return -EBUSY;

	if (!(pc->initialized & BIT_ULL(pwm->hwpwm)) &&
	    pwm->hwpwm >= PWM_NUM_GPIO)
		airoha_pwm_sipo_init(pc);

	if (index >= 0) {
		airoha_pwm_calc_bucket_config(pc, index, duty_ns, period_ns);
		airoha_pwm_config_flash_map(pc, pwm->hwpwm, index);
	} else {
		airoha_pwm_config_flash_map(pc, pwm->hwpwm, index);
		airoha_pwm_release_bucket_config(pc, pwm->hwpwm);
	}

	pc->initialized |= BIT_ULL(pwm->hwpwm);

	return 0;
}

static void airoha_pwm_disable(struct pwm_chip *chip, struct pwm_device *pwm)
{
	struct airoha_pwm *pc = container_of(chip, struct airoha_pwm, chip);

	/* Disable PWM and release the waveform */
	airoha_pwm_config_flash_map(pc, pwm->hwpwm, -1);
	airoha_pwm_release_bucket_config(pc, pwm->hwpwm);

	pc->initialized &= ~BIT_ULL(pwm->hwpwm);
	if (!(pc->initialized >> PWM_NUM_GPIO))
		airoha_pwm_clear_bit(pc, REG_SIPO_FLASH_MODE_CFG,
				     SERIAL_GPIO_FLASH_MODE);
}

static int airoha_pwm_apply(struct pwm_chip *chip, struct pwm_device *pwm,
			    const struct pwm_state *state)
{
	struct airoha_pwm *pc = container_of(chip, struct airoha_pwm, chip);
	u64 duty = state->enabled ? state->duty_cycle : 0;
	u64 period = state->period;

	/* Only normal polarity is supported */
	if (state->polarity == PWM_POLARITY_INVERSED)
		return -EINVAL;

	if (!state->enabled) {
		airoha_pwm_disable(chip, pwm);
		return 0;
	}

	if (period < PERIOD_MIN_NS)
		return -EINVAL;

	if (period > PERIOD_MAX_NS)
		period = PERIOD_MAX_NS;

	return airoha_pwm_config(pc, pwm, duty, period);
}

static int airoha_pwm_get_state(struct pwm_chip *chip, struct pwm_device *pwm,
				struct pwm_state *state)
{
	struct airoha_pwm *pc = container_of(chip, struct airoha_pwm, chip);
	int i;

	/* find hwpwm in waveform generator bucket */
	for (i = 0; i < ARRAY_SIZE(pc->bucket); i++) {
		if (pc->bucket[i].used & BIT_ULL(pwm->hwpwm)) {
			state->enabled = pc->initialized & BIT_ULL(pwm->hwpwm);
			state->polarity = PWM_POLARITY_NORMAL;
			state->period = pc->bucket[i].period_ns;
			state->duty_cycle = pc->bucket[i].duty_ns;
			break;
		}
	}

	if (i == ARRAY_SIZE(pc->bucket))
		state->enabled = false;

	return 0;
}

static const struct pwm_ops airoha_pwm_ops = {
	.get_state = airoha_pwm_get_state,
	.apply = airoha_pwm_apply,
	.owner = THIS_MODULE,
};

static int airoha_pwm_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct airoha_mfd *mfd;
	struct airoha_pwm *pc;

	/* Assign parent MFD of_node to dev */
	device_set_of_node_from_dev(dev, dev->parent);
	mfd = dev_get_drvdata(dev->parent);

	pc = devm_kzalloc(dev, sizeof(*pc), GFP_KERNEL);
	if (!pc)
		return -ENOMEM;

	pc->np = dev->of_node;
	pc->chip.dev = dev;
	pc->base = mfd->base;
	pc->chip.ops = &airoha_pwm_ops;
	pc->chip.npwm = PWM_NUM_GPIO + PWM_NUM_SIPO;

	platform_set_drvdata(pdev, pc);

	return pwmchip_add(&pc->chip);
}

static int airoha_pwm_remove(struct platform_device *pdev)
{
	struct airoha_pwm *pc = platform_get_drvdata(pdev);

	pwmchip_remove(&pc->chip);

	return 0;
}

static struct platform_driver airoha_pwm_driver = {
	.driver = {
		.name = "pwm-airoha",
	},
	.probe = airoha_pwm_probe,
	.remove = airoha_pwm_remove,
};
module_platform_driver(airoha_pwm_driver);

MODULE_AUTHOR("Lorenzo Bianconi <lorenzo@kernel.org>");
MODULE_AUTHOR("Markus Gothe <markus.gothe@genexis.eu>");
MODULE_AUTHOR("Benjamin Larsson <benjamin.larsson@genexis.eu>");
MODULE_DESCRIPTION("Airoha EN7581 PWM driver");
MODULE_LICENSE("GPL");
