/*
 * Nordic Semiconductor nRF51 SoC
 * http://infocenter.nordicsemi.com/pdf/nRF51_RM_v3.0.1.pdf
 *
 * Copyright 2018 Joel Stanley <joel@jms.id.au>
 *
 * This code is licensed under the GPL version 2 or later.  See
 * the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/arm/arm.h"
#include "hw/sysbus.h"
#include "hw/boards.h"
#include "hw/devices.h"
#include "hw/misc/unimp.h"
#include "exec/address-spaces.h"
#include "sysemu/sysemu.h"
#include "qemu/log.h"
#include "cpu.h"
#include "crypto/random.h"

#include "hw/arm/nrf51_soc.h"

#define IOMEM_BASE      0x40000000
#define IOMEM_SIZE      0x20000000

#define FICR_BASE       0x10000000
#define FICR_SIZE       0x000000fc

#define UICR_BASE       0x10001000
#define UICR_SIZE       0x100

#define FLASH_BASE      0x00000000
#define SRAM_BASE       0x20000000

#define PRIVATE_BASE    0xF0000000
#define PRIVATE_SIZE    0x10000000

#define TIMER_BASE      0x40008000

/*
 * The size and base is for the NRF51822 part. If other parts
 * are supported in the future, add a sub-class of NRF51SoC for
 * the specific variants
 */
#define NRF51822_FLASH_SIZE     (256 * 1024)
#define NRF51822_SRAM_SIZE      (16 * 1024)

#define BASE_TO_IRQ(base) ((base >> 12) & 0x1F)

/*
FICR Registers Assignments
CODEPAGESIZE      0x010      [4,
CODESIZE          0x014       5,
CLENR0            0x028       10,
PPFC              0x02C       11,
NUMRAMBLOCK       0x034       13,
SIZERAMBLOCKS     0x038       14,
SIZERAMBLOCK[0]   0x038       14,
SIZERAMBLOCK[1]   0x03C       15,
SIZERAMBLOCK[2]   0x040       16,
SIZERAMBLOCK[3]   0x044       17,
CONFIGID          0x05C       23,
DEVICEID[0]       0x060       24,
DEVICEID[1]       0x064       25,
ER[0]             0x080       32,
ER[1]             0x084       33,
ER[2]             0x088       34,
ER[3]             0x08C       35,
IR[0]             0x090       36,
IR[1]             0x094       37,
IR[2]             0x098       38,
IR[3]             0x09C       39,
DEVICEADDRTYPE    0x0A0       40,
DEVICEADDR[0]     0x0A4       41,
DEVICEADDR[1]     0x0A8       42,
OVERRIDEEN        0x0AC       43,
NRF_1MBIT[0]      0x0B0       44,
NRF_1MBIT[1]      0x0B4       45,
NRF_1MBIT[2]      0x0B8       46,
NRF_1MBIT[3]      0x0BC       47,
NRF_1MBIT[4]      0x0C0       48,
BLE_1MBIT[0]      0x0EC       59,
BLE_1MBIT[1]      0x0F0       60,
BLE_1MBIT[2]      0x0F4       61,
BLE_1MBIT[3]      0x0F8       62,
BLE_1MBIT[4]      0x0FC       63]
*/

static const uint32_t ficr_content[64] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0x00000400, 0x00000100, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000002,
        0x00002000, 0x00002000, 0x00002000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000003, 0x12345678, 0x9ABCDEF1,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, };

static uint64_t ficr_read(void *opaque, hwaddr offset, unsigned int size)
{
    qemu_log_mask(LOG_TRACE, "%s: 0x%" HWADDR_PRIx " [%u]\n",
            __func__, offset, size);

    if (offset > (ARRAY_SIZE(ficr_content) - size)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                "%s: bad read offset 0x%" HWADDR_PRIx "\n", __func__, offset);
        return 0;
    }

    return ficr_content[offset >> 2];
}

static const MemoryRegionOps ficr_ops = {
    .read = ficr_read,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .impl.unaligned = false,
};

static const uint32_t uicr_content[64] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, };

static uint64_t uicr_read(void *opaque, hwaddr offset, unsigned int size)
{
    qemu_log_mask(LOG_TRACE, "%s: 0x%" HWADDR_PRIx " [%u]\n",
            __func__, offset, size);

    if (offset > (ARRAY_SIZE(uicr_content) - size)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                "%s: bad read offset 0x%" HWADDR_PRIx "\n", __func__, offset);
        return 0;
    }

    return uicr_content[offset >> 2];
}

static const MemoryRegionOps uicr_ops = {
    .read = uicr_read,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .impl.unaligned = false,
};

static uint64_t clock_read(void *opaque, hwaddr addr, unsigned int size)
{
    qemu_log_mask(LOG_UNIMP, "%s: 0x%" HWADDR_PRIx " [%u]\n",
            __func__, addr, size);
    return 1;
}

static void clock_write(void *opaque, hwaddr addr, uint64_t data, unsigned int size)
{
    qemu_log_mask(LOG_UNIMP, "%s: 0x%" HWADDR_PRIx " <- 0x%" PRIx64 " [%u]\n", __func__, addr, data, size);
}

static const MemoryRegionOps clock_ops = {
    .read = clock_read,
    .write = clock_write
};

static uint64_t nvmc_read(void *opaque, hwaddr addr, unsigned int size)
{
    qemu_log_mask(LOG_TRACE, "%s: 0x%" HWADDR_PRIx " [%u]\n", __func__, addr, size);
    return 1;
}

static void nvmc_write(void *opaque, hwaddr addr, uint64_t data, unsigned int size)
{
    qemu_log_mask(LOG_TRACE, "%s: 0x%" HWADDR_PRIx " <- 0x%" PRIx64 " [%u]\n", __func__, addr, data, size);
}


static const MemoryRegionOps nvmc_ops = {
    .read = nvmc_read,
    .write = nvmc_write
};

static uint64_t rng_read(void *opaque, hwaddr addr, unsigned int size)
{
    uint64_t r = 0;

    qemu_log_mask(LOG_UNIMP, "%s: 0x%" HWADDR_PRIx " [%u]\n", __func__, addr, size);

    switch (addr) {
    case 0x508:
        qcrypto_random_bytes((uint8_t *)&r, 1, NULL);
        break;
    default:
        r = 1;
        break;
    }
    return r;
}

static void rng_write(void *opaque, hwaddr addr, uint64_t data, unsigned int size)
{
    qemu_log_mask(LOG_UNIMP, "%s: 0x%" HWADDR_PRIx " <- 0x%" PRIx64 " [%u]\n", __func__, addr, data, size);
}


static const MemoryRegionOps rng_ops = {
    .read = rng_read,
    .write = rng_write
};

static void nrf51_soc_realize(DeviceState *dev_soc, Error **errp)
{
    NRF51State *s = NRF51_SOC(dev_soc);
    MemoryRegion *mr;
    Error *err = NULL;

    if (!s->board_memory) {
        error_setg(errp, "memory property was not set");
        return;
    }

    object_property_set_link(OBJECT(&s->cpu), OBJECT(&s->container), "memory",
            &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    object_property_set_bool(OBJECT(&s->cpu), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    memory_region_add_subregion_overlap(&s->container, 0, s->board_memory, -1);

    memory_region_init_rom(&s->flash, OBJECT(s), "nrf51.flash", s->flash_size,
            &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    memory_region_add_subregion(&s->container, FLASH_BASE, &s->flash);

    memory_region_init_ram(&s->sram, NULL, "nrf51.sram", s->sram_size, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    memory_region_add_subregion(&s->container, SRAM_BASE, &s->sram);

    /* FICR */
    memory_region_init_io(&s->ficr, NULL, &ficr_ops, NULL, "nrf51_soc.ficr",
            FICR_SIZE);
    memory_region_set_readonly(&s->ficr, true);
    memory_region_add_subregion_overlap(&s->container, FICR_BASE, &s->ficr, 0);

    /* UICR */
    memory_region_init_io(&s->uicr, NULL, &uicr_ops, NULL, "nrf51_soc.uicr",
            UICR_SIZE);
    memory_region_set_readonly(&s->uicr, true);
    memory_region_add_subregion_overlap(&s->container, UICR_BASE, &s->uicr, 0);

    /* UART */
    object_property_set_bool(OBJECT(&s->uart), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    mr = sysbus_mmio_get_region(SYS_BUS_DEVICE(&s->uart), 0);
    memory_region_add_subregion_overlap(&s->container, UART_BASE, mr, 0);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->uart), 0,
                       qdev_get_gpio_in(DEVICE(&s->cpu),
                       BASE_TO_IRQ(UART_BASE)));

    create_unimplemented_device("nrf51_soc.io", IOMEM_BASE, IOMEM_SIZE);

    /* TIMER0 */
    object_property_set_bool(OBJECT(&s->timer), true, "realized", &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }

    mr = sysbus_mmio_get_region(SYS_BUS_DEVICE(&s->timer), 0);
    memory_region_add_subregion_overlap(&s->container, TIMER_BASE, mr, 0);
    sysbus_connect_irq(SYS_BUS_DEVICE(&s->timer), 0,
                       qdev_get_gpio_in(DEVICE(&s->cpu),
                       BASE_TO_IRQ(TIMER_BASE)));

    memory_region_init_io(&s->clock, NULL, &clock_ops, NULL, "nrf51_soc.clock", 0x1000);
    memory_region_add_subregion_overlap(&s->container, IOMEM_BASE, &s->clock, -1);

    memory_region_init_io(&s->nvmc, NULL, &nvmc_ops, NULL, "nrf51_soc.nvmc", 0x1000);
    memory_region_add_subregion_overlap(&s->container, 0x4001E000, &s->nvmc, -1);

    memory_region_init_io(&s->rng, NULL, &rng_ops, NULL, "nrf51_soc.rng", 0x1000);
    memory_region_add_subregion_overlap(&s->container, 0x4000D000, &s->rng, -1);

    create_unimplemented_device("nrf51_soc.private",
                                PRIVATE_BASE, PRIVATE_SIZE);
}

static void nrf51_soc_init(Object *obj)
{
    NRF51State *s = NRF51_SOC(obj);

    memory_region_init(&s->container, obj, "nrf51-container", UINT64_MAX);

    sysbus_init_child_obj(OBJECT(s), "armv6m", OBJECT(&s->cpu), sizeof(s->cpu),
                          TYPE_ARMV7M);
    qdev_prop_set_string(DEVICE(&s->cpu), "cpu-type",
                         ARM_CPU_TYPE_NAME("cortex-m0"));
    qdev_prop_set_uint32(DEVICE(&s->cpu), "num-irq", 32);

    sysbus_init_child_obj(obj, "uart", &s->uart, sizeof(s->uart),
                           TYPE_NRF51_UART);
    object_property_add_alias(obj, "serial0", OBJECT(&s->uart), "chardev",
                              &error_abort);

    object_initialize(&s->timer, sizeof(s->timer), TYPE_NRF51_TIMER);
    object_property_add_child(obj, "timer0", OBJECT(&s->timer), &error_abort);
    qdev_set_parent_bus(DEVICE(&s->timer), sysbus_get_default());

}

static Property nrf51_soc_properties[] = {
    DEFINE_PROP_LINK("memory", NRF51State, board_memory, TYPE_MEMORY_REGION,
                     MemoryRegion *),
    DEFINE_PROP_UINT32("sram-size", NRF51State, sram_size, NRF51822_SRAM_SIZE),
    DEFINE_PROP_UINT32("flash-size", NRF51State, flash_size,
                       NRF51822_FLASH_SIZE),
    DEFINE_PROP_END_OF_LIST(),
};

static void nrf51_soc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = nrf51_soc_realize;
    dc->props = nrf51_soc_properties;
}

static const TypeInfo nrf51_soc_info = {
    .name          = TYPE_NRF51_SOC,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(NRF51State),
    .instance_init = nrf51_soc_init,
    .class_init    = nrf51_soc_class_init,
};

static void nrf51_soc_types(void)
{
    type_register_static(&nrf51_soc_info);
}
type_init(nrf51_soc_types)
