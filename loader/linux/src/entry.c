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

#include "loader_interface.h"

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/suspend.h>

static int
dev_open(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "[bareflank_loader]: dev_open\n");
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
    printk(KERN_INFO "[bareflank_loader]: dev_release\n");
    return 0;
}

static long
dev_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    printk(KERN_INFO "[bareflank_loader]: dev_unlocked_ioctl\n");
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
    printk(KERN_INFO "[bareflank_loader]: dev_reboot\n");
    return NOTIFY_DONE;
}

static int
resume(void)
{
    printk(KERN_INFO "[bareflank_loader]: resume\n");
    return NOTIFY_DONE;
}

static int
suspend(void)
{
    printk(KERN_INFO "[bareflank_loader]: suspend\n");
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
    printk(KERN_INFO "[bareflank_loader]: dev_init\n");

    register_reboot_notifier(&reboot_notifier_block);
    register_pm_notifier(&pm_notifier_block);

    if (misc_register(&bareflank_dev) != 0) {
        printk(KERN_ALERT "[bareflank_loader]: misc_register failed\n");
        return -EPERM;
    }

    return 0;
}

void
dev_exit(void)
{
    printk(KERN_INFO "[bareflank_loader]: dev_exit\n");

    misc_deregister(&bareflank_dev);
    unregister_pm_notifier(&pm_notifier_block);
    unregister_reboot_notifier(&reboot_notifier_block);

    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
