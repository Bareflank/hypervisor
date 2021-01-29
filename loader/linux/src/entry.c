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
dev_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
        case LOADER_START_VMM: {
            if (start_vmm((struct start_vmm_args_t const *)arg)) {
                BFERROR("start_vmm failed\n");
                return ((long)-EPERM);
            }
            break;
        }
        case LOADER_STOP_VMM: {
            if (stop_vmm((struct stop_vmm_args_t const *)arg)) {
                BFERROR("stop_vmm failed\n");
                return ((long)-EPERM);
            }
            break;
        }
        case LOADER_DUMP_VMM: {
            if (dump_vmm((struct dump_vmm_args_t const *)arg)) {
                BFERROR("dump_vmm failed\n");
                return ((long)-EPERM);
            }
            break;
        }
        default: {
            BFERROR("invalid ioctl cmd: 0x%x\n", cmd);
            return ((long)-EINVAL);
        }
    };

    return ((long)0);
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
    BFDEBUG("\n");
    return NOTIFY_DONE;
}

static int
resume(void)
{
    BFDEBUG("resume not yet supported\n");
    return NOTIFY_BAD;
}

static int
suspend(void)
{
    BFDEBUG("suspend not yet supported\n");
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

    if (loader_init()) {
        BFERROR("loader_init failed\n");
        goto loader_init_failed;
    }

    if (misc_register(&bareflank_dev)) {
        BFERROR("misc_register failed\n");
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
