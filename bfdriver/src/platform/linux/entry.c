/*
 * Bareflank Hypervisor
 * Copyright (C) 2015 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#include <linux/reboot.h>

#include <common.h>

#include <bfdebug.h>
#include <bftypes.h>
#include <bfconstants.h>
#include <bfdriverinterface.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

uint64_t g_vcpuid = 0;
uint64_t g_module_length = 0;

struct pmodule_t {
    const char *data;
    int64_t size;
};

uint64_t g_num_pmodules = 0;
struct pmodule_t pmodules[MAX_NUM_MODULES] = { 0 };

/* -------------------------------------------------------------------------- */
/* Misc Device                                                                */
/* -------------------------------------------------------------------------- */

static int
dev_open(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    BFDEBUG("dev_open succeeded\n");
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    BFDEBUG("dev_release succeeded\n");
    return 0;
}

static long
ioctl_add_module(const char *file)
{
    char *buf;
    int64_t ret;

    if (g_num_pmodules >= MAX_NUM_MODULES) {
        BFALERT("IOCTL_ADD_MODULE: too many modules have been loaded\n");
        return BF_IOCTL_FAILURE;
    }

    buf = platform_alloc_rw(g_module_length);
    if (buf == NULL) {
        BFALERT("IOCTL_ADD_MODULE: failed to allocate memory for the module\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_from_user(buf, file, g_module_length);
    if (ret != 0) {
        BFALERT("IOCTL_ADD_MODULE: failed to copy memory from userspace\n");
        goto failed;
    }

    ret = common_add_module(buf, g_module_length);
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_ADD_MODULE: common_add_module failed: %p - %s\n", \
                (void *)ret, ec_to_str(ret));
        goto failed;
    }

    pmodules[g_num_pmodules].data = buf;
    pmodules[g_num_pmodules].size = g_module_length;

    g_num_pmodules++;

    BFDEBUG("IOCTL_ADD_MODULE: succeeded\n");
    return BF_IOCTL_SUCCESS;

failed:

    platform_free_rw(buf, g_module_length);

    BFALERT("IOCTL_ADD_MODULE: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
ioctl_add_module_length(uint64_t *len)
{
    int64_t ret;

    if (len == 0) {
        BFALERT("IOCTL_ADD_MODULE_LENGTH: failed with len == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_from_user(&g_module_length, len, sizeof(uint64_t));
    if (ret != 0) {
        BFALERT("IOCTL_ADD_MODULE_LENGTH: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    BFDEBUG("IOCTL_ADD_MODULE_LENGTH: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
ioctl_unload_vmm(void)
{
    int i;
    int64_t ret;
    long status = BF_IOCTL_SUCCESS;

    ret = common_unload_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_UNLOAD_VMM: common_unload_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        status = BF_IOCTL_FAILURE;
    }

    for (i = 0; i < g_num_pmodules; i++) {
        platform_free_rw(pmodules[i].data, pmodules[i].size);
    }

    g_num_pmodules = 0;
    platform_memset(&pmodules, 0, sizeof(pmodules));

    if (status == BF_IOCTL_SUCCESS) {
        BFDEBUG("IOCTL_UNLOAD_VMM: succeeded\n");
    }

    return status;
}

static long
ioctl_load_vmm(void)
{
    int64_t ret;

    ret = common_load_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_LOAD_VMM: common_load_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto failure;
    }

    BFDEBUG("IOCTL_LOAD_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;

failure:

    ioctl_unload_vmm();
    return BF_IOCTL_FAILURE;
}

static long
ioctl_stop_vmm(void)
{
    int64_t ret;
    long status = BF_IOCTL_SUCCESS;

    ret = common_stop_vmm();

    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_STOP_VMM: common_stop_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        status = BF_IOCTL_FAILURE;
    }

    if (status == BF_IOCTL_SUCCESS) {
        BFDEBUG("IOCTL_STOP_VMM: succeeded\n");
    }

    return status;
}

static long
ioctl_start_vmm(void)
{
    int64_t ret;

    ret = common_start_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_START_VMM: common_start_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto failure;
    }

    BFDEBUG("IOCTL_START_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;

failure:

    ioctl_stop_vmm();
    return BF_IOCTL_FAILURE;
}

static long
ioctl_dump_vmm(struct debug_ring_resources_t *user_drr)
{
    int64_t ret;
    struct debug_ring_resources_t *drr = 0;

    ret = common_dump_vmm(&drr, g_vcpuid);
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_DUMP_VMM: common_dump_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        return BF_IOCTL_FAILURE;
    }

    ret = copy_to_user(user_drr, drr, sizeof(struct debug_ring_resources_t));
    if (ret != 0) {
        BFALERT("IOCTL_DUMP_VMM: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    BFDEBUG("IOCTL_DUMP_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
ioctl_vmm_status(int64_t *status)
{
    int64_t ret;
    int64_t vmm_status = common_vmm_status();

    if (status == 0) {
        BFALERT("IOCTL_VMM_STATUS: common_vmm_status failed: NULL\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_to_user(status, &vmm_status, sizeof(int64_t));
    if (ret != 0) {
        BFALERT("IOCTL_VMM_STATUS: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    return BF_IOCTL_SUCCESS;
}

static long
ioctl_set_vcpuid(uint64_t *vcpuid)
{
    int64_t ret;

    if (vcpuid == 0) {
        BFALERT("IOCTL_SET_VCPUID: failed with vcpuid == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_from_user(&g_vcpuid, vcpuid, sizeof(uint64_t));
    if (ret != 0) {
        BFALERT("IOCTL_SET_VCPUID: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    return BF_IOCTL_SUCCESS;
}

static long
dev_unlocked_ioctl(struct file *file,
                   unsigned int cmd,
                   unsigned long arg)
{
    (void) file;

    switch (cmd) {
        case IOCTL_ADD_MODULE:
            return ioctl_add_module((char *)arg);

        case IOCTL_ADD_MODULE_LENGTH:
            return ioctl_add_module_length((uint64_t *)arg);

        case IOCTL_LOAD_VMM:
            return ioctl_load_vmm();

        case IOCTL_UNLOAD_VMM:
            return ioctl_unload_vmm();

        case IOCTL_START_VMM:
            return ioctl_start_vmm();

        case IOCTL_STOP_VMM:
            return ioctl_stop_vmm();

        case IOCTL_DUMP_VMM:
            return ioctl_dump_vmm((struct debug_ring_resources_t *)arg);

        case IOCTL_VMM_STATUS:
            return ioctl_vmm_status((int64_t *)arg);

        case IOCTL_SET_VCPUID:
            return ioctl_set_vcpuid((uint64_t *)arg);

        default:
            return -EINVAL;
    }
}

static struct file_operations fops = {
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl,
};

static struct miscdevice bareflank_dev = {
    MISC_DYNAMIC_MINOR,
    BAREFLANK_NAME,
    &fops
};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
dev_reboot(struct notifier_block *nb,
           unsigned long code, void *unused)
{
    (void) nb;
    (void) code;
    (void) unused;

    common_fini();

    return NOTIFY_DONE;
}

static struct notifier_block bareflank_notifier_block = {
    .notifier_call = dev_reboot
};

int
dev_init(void)
{
    register_reboot_notifier(&bareflank_notifier_block);

    if (misc_register(&bareflank_dev) != 0) {
        BFALERT("misc_register failed\n");
        return -EPERM;
    }

    if (common_init() != 0) {
        return -EPERM;
    }

    BFDEBUG("dev_init succeeded\n");
    return 0;
}

void
dev_exit(void)
{
    common_fini();

    misc_deregister(&bareflank_dev);
    unregister_reboot_notifier(&bareflank_notifier_block);

    BFDEBUG("dev_exit succeeded\n");
    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
