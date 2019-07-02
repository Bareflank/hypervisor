/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/suspend.h>

#include <common.h>

#include <bfdebug.h>
#include <bftypes.h>
#include <bfconstants.h>
#include <bfdriverinterface.h>

uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4);

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

static uint64_t g_vcpuid = 0;
static uint64_t g_module_length = 0;

struct pmodule_t {
    char *data;
    int64_t size;
};

uint64_t g_num_pmodules = 0;
struct pmodule_t pmodules[MAX_NUM_MODULES] = { 0 };

/* -------------------------------------------------------------------------- */
/* Status                                                                     */
/* -------------------------------------------------------------------------- */

static int g_status = 0;

#define STATUS_STOPPED 0
#define STATUS_RUNNING 1
#define STATUS_SUSPEND 2

DEFINE_MUTEX(g_status_mutex);

/* -------------------------------------------------------------------------- */
/* Misc Device                                                                */
/* -------------------------------------------------------------------------- */

static int
dev_open(struct inode *inode, struct file *file)
{ return 0; }

static int
dev_release(struct inode *inode, struct file *file)
{ return 0; }

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
        goto IOCTL_FAILURE;
    }

    ret = common_add_module(buf, g_module_length);
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_ADD_MODULE: common_add_module failed: %p - %s\n", \
                (void *)ret, ec_to_str(ret));
        goto IOCTL_FAILURE;
    }

    pmodules[g_num_pmodules].data = buf;
    pmodules[g_num_pmodules].size = g_module_length;

    g_num_pmodules++;

    return BF_IOCTL_SUCCESS;

IOCTL_FAILURE:

    platform_free_rw(buf, g_module_length);
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

    return BF_IOCTL_SUCCESS;
}

static long
ioctl_unload_vmm(void)
{
    int i;
    int64_t ret;

    ret = common_unload_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_UNLOAD_VMM: common_unload_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto IOCTL_FAILURE;
    }

    for (i = 0; i < g_num_pmodules; i++) {
        platform_free_rw(pmodules[i].data, pmodules[i].size);
    }

    g_num_pmodules = 0;
    platform_memset(&pmodules, 0, sizeof(pmodules));

    return BF_IOCTL_SUCCESS;

IOCTL_FAILURE:

    return BF_IOCTL_FAILURE;
}

static long
ioctl_load_vmm(void)
{
    int64_t ret;

    ret = common_load_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_LOAD_VMM: common_load_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto IOCTL_FAILURE;
    }

    return BF_IOCTL_SUCCESS;

IOCTL_FAILURE:

    ioctl_unload_vmm();
    return BF_IOCTL_FAILURE;
}

static long
ioctl_stop_vmm(void)
{
    int64_t ret;
    mutex_lock(&g_status_mutex);

    ret = common_stop_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_STOP_VMM: common_stop_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto IOCTL_FAILURE;
    }

    g_status = STATUS_STOPPED;

    mutex_unlock(&g_status_mutex);
    return BF_IOCTL_SUCCESS;

IOCTL_FAILURE:

    mutex_unlock(&g_status_mutex);
    return BF_IOCTL_FAILURE;
}

static long
ioctl_start_vmm(void)
{
    int64_t ret;
    mutex_lock(&g_status_mutex);

    ret = common_start_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_START_VMM: common_start_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto IOCTL_FAILURE;
    }

    g_status = STATUS_RUNNING;

    mutex_unlock(&g_status_mutex);
    return BF_IOCTL_SUCCESS;

IOCTL_FAILURE:

    common_stop_vmm();

    mutex_unlock(&g_status_mutex);
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
ioctl_vmcall(struct ioctl_vmcall_args_t *user_args)
{
    int64_t ret;
    struct ioctl_vmcall_args_t args;

    if (user_args == 0) {
        BFALERT("IOCTL_CALL: failed with args == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_from_user(&args, user_args, sizeof(struct ioctl_vmcall_args_t));
    if (ret != 0) {
        BFALERT("IOCTL_CALL: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    mutex_lock(&g_status_mutex);

    switch (g_status) {
        case STATUS_RUNNING:
            args.reg1 = _vmcall(args.reg1, args.reg2, args.reg3, args.reg4);
            break;

        case STATUS_SUSPEND:
            args.reg1 = SUSPEND;
            break;

        default:
            args.reg1 = FAILURE;
            break;
    };

    mutex_unlock(&g_status_mutex);

    args.reg2 = 0;
    args.reg3 = 0;
    args.reg4 = 0;

    ret = copy_to_user(user_args, &args, sizeof(struct ioctl_vmcall_args_t));
    if (ret != 0) {
        BFALERT("IOCTL_CALL: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    return BF_IOCTL_SUCCESS;
}

static long
dev_unlocked_ioctl(
    struct file *file, unsigned int cmd, unsigned long arg)
{
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

        case IOCTL_VMCALL:
            return ioctl_vmcall((struct ioctl_vmcall_args_t *)arg);

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
    .minor = MISC_DYNAMIC_MINOR,
    .name = BAREFLANK_NAME,
    .fops = &fops,
    .mode = 0666
};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
dev_reboot(
    struct notifier_block *nb, unsigned long code, void *unused)
{
    mutex_lock(&g_status_mutex);

    common_fini();
    g_status = STATUS_STOPPED;

    mutex_unlock(&g_status_mutex);
    return NOTIFY_DONE;
}

static int
resume(void)
{
    mutex_lock(&g_status_mutex);

    if (g_status != STATUS_SUSPEND) {
        mutex_unlock(&g_status_mutex);
        return NOTIFY_DONE;
    }

    if (common_start_vmm() != BF_SUCCESS) {

        common_fini();
        g_status = STATUS_STOPPED;

        mutex_unlock(&g_status_mutex);
        return -EPERM;
    }

    g_status = STATUS_RUNNING;

    mutex_unlock(&g_status_mutex);
    return NOTIFY_DONE;
}

static int
suspend(void)
{
    mutex_lock(&g_status_mutex);

    if (g_status != STATUS_RUNNING) {
        mutex_unlock(&g_status_mutex);
        return NOTIFY_DONE;
    }

    if (common_stop_vmm() != BF_SUCCESS) {

        common_fini();
        g_status = STATUS_STOPPED;

        mutex_unlock(&g_status_mutex);
        return -EPERM;
    }

    g_status = STATUS_SUSPEND;

    mutex_unlock(&g_status_mutex);
    return NOTIFY_DONE;
}

int
dev_pm(
    struct notifier_block *nb, unsigned long code, void *unused)
{
    switch (code) {
        case PM_SUSPEND_PREPARE:
        case PM_HIBERNATION_PREPARE:
        case PM_RESTORE_PREPARE:
            return suspend();

        case PM_POST_SUSPEND:
        case PM_POST_HIBERNATION:
        case PM_POST_RESTORE:
            return resume();

        default:
            break;
    }

    return NOTIFY_DONE;
}

static struct notifier_block reboot_notifier_block = {
    .notifier_call = dev_reboot
};

static struct notifier_block pm_notifier_block = {
    .notifier_call = dev_pm
};

int
dev_init(void)
{
    register_reboot_notifier(&reboot_notifier_block);
    register_pm_notifier(&pm_notifier_block);

    if (misc_register(&bareflank_dev) != 0) {
        BFALERT("misc_register failed\n");
        goto INIT_FAILURE;
    }

    if (common_init() != 0) {
        BFALERT("common_init failed\n");
        goto INIT_FAILURE;
    }

    g_status = STATUS_STOPPED;
    mutex_init(&g_status_mutex);

    return 0;

INIT_FAILURE:

    return -EPERM;
}

void
dev_exit(void)
{
    mutex_lock(&g_status_mutex);

    common_fini();
    g_status = STATUS_STOPPED;

    misc_deregister(&bareflank_dev);
    unregister_pm_notifier(&pm_notifier_block);
    unregister_reboot_notifier(&reboot_notifier_block);

    mutex_unlock(&g_status_mutex);
    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
