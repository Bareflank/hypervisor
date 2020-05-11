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

#include <loader_debug.h>
#include <loader_interface.h>
#include <loader_types.h>

#include <loader_common.h>

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/suspend.h>

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
        case BAREFLANK_LOADER_START_VMM: {
            int64_t ret = common_start_vmm();
            if (ret != 0) {
                return ret;
            }
            break;
        }

        case BAREFLANK_LOADER_STOP_VMM: {
            int64_t ret = common_stop_vmm();
            if (ret != 0) {
                return ret;
            }
            break;
        }

        case BAREFLANK_LOADER_DUMP_VMM: {
            int64_t ret = common_dump_vmm();
            if (ret != 0) {
                return ret;
            }
            break;
        }

        default: {
            BFERROR("invalid ioctl cmd: 0x%x\n", cmd);
            return -EINVAL;
        }
    };

    return 0;
}

static struct file_operations fops = {
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl,
};

static struct miscdevice bareflank_dev = {
    .minor = MISC_DYNAMIC_MINOR, .name = BAREFLANK_LOADER_NAME, .fops = &fops, .mode = 0666};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
dev_reboot(struct notifier_block *nb, unsigned long code, void *unused)
{
    BFDEBUG("dev_reboot\n");
    return NOTIFY_DONE;
}

static int
resume(void)
{
    BFDEBUG("resume\n");
    return NOTIFY_DONE;
}

static int
suspend(void)
{
    BFDEBUG("suspend\n");
    return NOTIFY_DONE;
}

int
dev_pm(struct notifier_block *nb, unsigned long code, void *unused)
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

static struct notifier_block reboot_notifier_block = {.notifier_call = dev_reboot};
static struct notifier_block pm_notifier_block = {.notifier_call = dev_pm};

int
dev_init(void)
{
    int64_t ret = 0;

    register_reboot_notifier(&reboot_notifier_block);
    register_pm_notifier(&pm_notifier_block);

    if (misc_register(&bareflank_dev) != 0) {
        BFERROR("misc_register failed\n");
        return -EPERM;
    }

    ret = common_init();
    if (ret != 0) {
        return ret;
    }

    return 0;
}

void
dev_exit(void)
{
    BFDEBUG("dev_exit\n");

    common_fini();
    misc_deregister(&bareflank_dev);
    unregister_pm_notifier(&pm_notifier_block);
    unregister_reboot_notifier(&reboot_notifier_block);

    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
