
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/cpumask.h>
#include <linux/sched.h>
#include <linux/notifier.h>
#include <linux/reboot.h>

#include <debug.h>
#include <common.h>
#include <platform.h>
#include <constants.h>
#include <driver_entry_interface.h>

/* ========================================================================== */
/* Global                                                                     */
/* ========================================================================== */

int64_t g_module_length = 0;

int64_t g_num_files = 0;
char *files[MAX_NUM_MODULES] = {0};
int64_t files_size[MAX_NUM_MODULES] = { 0 };

typedef long (*set_affinity_fn)(pid_t, const struct cpumask *);
set_affinity_fn set_cpu_affinity;

/* ========================================================================== */
/* Misc Device                                                                */
/* ========================================================================== */

static int
dev_open(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    DEBUG("dev_open succeeded\n");
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    DEBUG("dev_release succeeded\n");
    return 0;
}

static long
ioctl_add_module(char *file)
{
    int ret;
    char *buf;

    if (g_num_files >= MAX_NUM_MODULES)
    {
        ALERT("IOCTL_ADD_MODULE: too many modules have been loaded\n");
        return BF_IOCTL_FAILURE;
    }

    /*
     * On Linux, we are not given a size for the IOCTL. Appearently
     * it is common practice to seperate this information into two
     * different IOCTLs, which is what we do here. This however means
     * that we have to store state, so userspace has to be careful
     * to send these IOCTLs in the correct order.
     *
     * Linux also does not copy userspace memory for us, so we need
     * to do this ourselves. As a result, we alloc memory for the
     * buffer that userspace is providing us so that we can copy this
     * memory from userspace as needed.
     */

    buf = platform_alloc(g_module_length);
    if (buf == NULL)
    {
        ALERT("IOCTL_ADD_MODULE: failed to allocate memory for the module\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_from_user(buf, file, g_module_length);
    if (ret != 0)
    {
        ALERT("IOCTL_ADD_MODULE: failed to copy memory from userspace\n");
        goto failed;
    }

    ret = common_add_module(buf, g_module_length);
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_ADD_MODULE: failed to add module\n");
        goto failed;
    }

    files[g_num_files] = buf;
    files_size[g_num_files] = g_module_length;

    g_num_files++;

    DEBUG("IOCTL_ADD_MODULE: succeeded\n");
    return BF_IOCTL_SUCCESS;

failed:

    vfree(buf);

    DEBUG("IOCTL_ADD_MODULE: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
ioctl_add_module_length(int64_t *len)
{
    int ret;

    if (len == 0)
    {
        ALERT("IOCTL_ADD_MODULE_LENGTH: failed with len == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_from_user(&g_module_length, len, sizeof(int64_t));
    if (ret != 0)
    {
        ALERT("IOCTL_ADD_MODULE_LENGTH: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    DEBUG("IOCTL_ADD_MODULE_LENGTH: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
ioctl_unload_vmm(void)
{
    int i;
    int ret;
    long status = BF_IOCTL_SUCCESS;

    ret = common_unload_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_UNLOAD_VMM: failed to unload vmm: %d\n", ret);
        status = BF_IOCTL_FAILURE;
    }

    for (i = 0; i < g_num_files; i++)
        platform_free(files[i], files_size[i]);

    g_num_files = 0;

    if (status == BF_IOCTL_SUCCESS)
        DEBUG("IOCTL_UNLOAD_VMM: succeeded\n");

    return status;
}

static long
ioctl_load_vmm(void)
{
    int ret;

    ret = common_load_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_LOAD_VMM: failed to load vmm: %d\n", ret);
        goto failure;
    }

    DEBUG("IOCTL_LOAD_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;

failure:

    ioctl_unload_vmm();
    return BF_IOCTL_FAILURE;
}

static long
ioctl_stop_vmm(void)
{
    int ret;
    long status = BF_IOCTL_SUCCESS;

    ret = common_stop_vmm();

    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_STOP_VMM: failed to stop vmm: %d\n", ret);
        status = BF_IOCTL_FAILURE;
    }

    if (status == BF_IOCTL_SUCCESS)
        DEBUG("IOCTL_STOP_VMM: succeeded\n");

    return status;
}

static long
ioctl_start_vmm(void)
{
    int ret;

    ret = common_start_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_START_VMM: failed to start vmm: %d\n", ret);
        goto failure;
    }

    DEBUG("IOCTL_START_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;

failure:

    ioctl_stop_vmm();
    return BF_IOCTL_FAILURE;
}

static long
ioctl_dump_vmm(struct debug_ring_resources_t *user_drr)
{
    int ret;
    struct debug_ring_resources_t *drr = 0;

    ret = common_dump_vmm(&drr);
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_DUMP_VMM: failed to dump vmm: %d\n", ret);
        return BF_IOCTL_FAILURE;
    }

    ret = copy_to_user(user_drr, drr, sizeof(struct debug_ring_resources_t));
    if (ret != 0)
    {
        ALERT("IOCTL_DUMP_VMM: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    DEBUG("IOCTL_DUMP_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
ioctl_vmm_status(int64_t *status)
{
    int ret;
    int64_t vmm_status = common_vmm_status();

    if (status == 0)
    {
        ALERT("IOCTL_VMM_STATUS: failed with status == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_to_user(status, &vmm_status, sizeof(int64_t));
    if (ret != 0)
    {
        ALERT("IOCTL_VMM_STATUS: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    DEBUG("IOCTL_VMM_STATUS: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static void
helper_fini(void)
{
    set_cpu_affinity(current->pid, cpumask_of(0));
    common_fini();
}

static long
dev_unlocked_ioctl(struct file *file,
                   unsigned int cmd,
                   unsigned long arg)
{
    (void) file;

    set_cpu_affinity(current->pid, cpumask_of(0));

    switch (cmd)
    {
        case IOCTL_ADD_MODULE:
            return ioctl_add_module((char *)arg);

        case IOCTL_ADD_MODULE_LENGTH:
            return ioctl_add_module_length((int64_t *)arg);

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

        default:
            return -EINVAL;
    }
}

static struct file_operations fops =
{
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl,
};

static struct miscdevice bareflank_dev =
{
    MISC_DYNAMIC_MINOR,
    BAREFLANK_NAME,
    &fops
};

/* ========================================================================== */
/* Entry / Exit                                                               */
/* ========================================================================== */

int
dev_reboot(struct notifier_block *nb,
           unsigned long code, void *unused)
{
    (void) nb;
    (void) code;
    (void) unused;

    helper_fini();

    return NOTIFY_DONE;
}

static struct notifier_block bareflank_notifier_block =
{
    .notifier_call = dev_reboot
};

int
dev_init(void)
{
    int ret;

    register_reboot_notifier(&bareflank_notifier_block);

    set_cpu_affinity = (set_affinity_fn)kallsyms_lookup_name("sched_setaffinity");
    if (set_cpu_affinity == NULL)
    {
        ALERT("Failed to locate sched_setaffinity, to avoid problems, not continuing to load bareflank\n");
        return -1;
    }

    if ((ret = misc_register(&bareflank_dev)) != 0)
    {
        ALERT("misc_register failed\n");
        return ret;
    }

    if ((ret = common_init()) != 0)
    {
        ALERT("common_init failed\n");
        return ret;
    }

    DEBUG("dev_init succeeded\n");
    return 0;
}

void
dev_exit(void)
{
    helper_fini();

    misc_deregister(&bareflank_dev);
    unregister_reboot_notifier(&bareflank_notifier_block);

    DEBUG("dev_exit succeeded\n");
    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
