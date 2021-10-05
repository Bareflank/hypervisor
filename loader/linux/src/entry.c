/* SPDX-License-Identifier: SPDX-License-Identifier: GPL-2.0 OR MIT */

/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <debug.h>
#include <dump_vmm.h>
#include <dump_vmm_args_t.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/suspend.h>
#include <loader_fini.h>
#include <loader_init.h>
#include <loader_platform_interface.h>
#include <platform.h>
#include <serial_init.h>
#include <start_vmm.h>
#include <start_vmm_args_t.h>
#include <stop_vmm.h>
#include <stop_vmm_args_t.h>
#include <types.h>

static int
dev_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
    return 0;
}

static long
dispatch_start_vmm(void *const ioctl_args)
{
    int64_t ret;
    struct start_vmm_args_t args;

    ret = platform_copy_from_user(
        &args, ioctl_args, sizeof(struct start_vmm_args_t));
    if (ret) {
        bferror("platform_copy_from_user failed");
        return -EPERM;
    }

    ret = start_vmm(&args);
    if (ret) {
        bferror("start_vmm failed");
        return -EPERM;
    }

    return 0;
}

static long
dispatch_stop_vmm(void *const ioctl_args)
{
    int64_t ret;
    struct stop_vmm_args_t args;

    ret = platform_copy_from_user(
        &args, ioctl_args, sizeof(struct stop_vmm_args_t));
    if (ret) {
        bferror("platform_copy_from_user failed");
        return -EPERM;
    }

    ret = stop_vmm(&args);
    if (ret) {
        bferror("stop_vmm failed");
        return -EPERM;
    }

    return 0;
}

static long
dispatch_dump_vmm(void *const ioctl_args)
{
    int64_t ret;
    struct dump_vmm_args_t *args;

    args = (struct dump_vmm_args_t *)platform_alloc(
        sizeof(struct dump_vmm_args_t));
    if (((void *)0) == args) {
        bferror("platform_alloc failed");
        return LOADER_FAILURE;
    }

    ret = platform_copy_from_user(
        args, ioctl_args, sizeof(struct dump_vmm_args_t));
    if (ret) {
        bferror("platform_copy_from_user failed");
        goto platform_copy_from_user_failed;
    }

    ret = dump_vmm(args);
    if (ret) {
        bferror("dump_vmm failed");
        goto dump_vmm_failed;
    }

    ret =
        platform_copy_to_user(ioctl_args, args, sizeof(struct dump_vmm_args_t));
    if (ret) {
        bferror("platform_copy_to_user failed");
        goto platform_copy_to_user_failed;
    }

    platform_free(args, sizeof(struct dump_vmm_args_t));
    return 0;

platform_copy_to_user_failed:
dump_vmm_failed:
platform_copy_from_user_failed:

    platform_free(args, sizeof(struct dump_vmm_args_t));
    return -EPERM;
}

static long
dev_unlocked_ioctl(
    struct file *file, unsigned int cmd, unsigned long ioctl_args)
{
    switch (cmd) {
        case LOADER_START_VMM: {
            return dispatch_start_vmm((void *)ioctl_args);
        }
        case LOADER_STOP_VMM: {
            return dispatch_stop_vmm((void *)ioctl_args);
        }
        case LOADER_DUMP_VMM: {
            return dispatch_dump_vmm((void *)ioctl_args);
        }
        default: {
            bferror_x64("invalid ioctl cmd", cmd);
            return -EINVAL;
        }
    };

    return 0;
}

static struct file_operations fops = {
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl};

static struct miscdevice bareflank_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = LOADER_NAME,
    .fops = &fops,
    .mode = 0666};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
dev_reboot(struct notifier_block *nb, unsigned long code, void *unused)
{
    return NOTIFY_DONE;
}

static int
resume(void)
{
    return NOTIFY_BAD;
}

static int
suspend(void)
{
    return NOTIFY_BAD;
}

int
dev_pm(struct notifier_block *nb, unsigned long code, void *unused)
{
    int ret;

    switch (code) {
        case PM_SUSPEND_PREPARE:
        case PM_HIBERNATION_PREPARE:
        case PM_RESTORE_PREPARE: {
            ret = suspend();
            break;
        }

        case PM_POST_SUSPEND:
        case PM_POST_HIBERNATION:
        case PM_POST_RESTORE: {
            ret = resume();
            break;
        }

        default: {
            ret = NOTIFY_DONE;
            break;
        }
    }

    return ret;
}

static struct notifier_block reboot_notifier_block = {
    .notifier_call = dev_reboot};

static struct notifier_block pm_notifier_block = {.notifier_call = dev_pm};

int
dev_init(void)
{
    register_reboot_notifier(&reboot_notifier_block);
    register_pm_notifier(&pm_notifier_block);

    serial_init();

    if (loader_init()) {
        bferror("loader_init failed");
        goto loader_init_failed;
    }

    if (misc_register(&bareflank_dev)) {
        bferror("misc_register failed");
        goto misc_register_failed;
    }

    return 0;

    misc_deregister(&bareflank_dev);
misc_register_failed:

    loader_fini();
loader_init_failed:

    unregister_pm_notifier(&pm_notifier_block);
    unregister_reboot_notifier(&reboot_notifier_block);

    return -EPERM;
}

void
dev_exit(void)
{
    misc_deregister(&bareflank_dev);
    loader_fini();
    unregister_pm_notifier(&pm_notifier_block);
    unregister_reboot_notifier(&reboot_notifier_block);
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("Dual MIT/GPL");
