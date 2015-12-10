
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/cpumask.h>

#include <debug.h>
#include <common.h>
#include <platform.h>
#include <driver_entry_interface.h>

/* ========================================================================== */
/* Global                                                                     */
/* ========================================================================== */

int32_t g_module_length = 0;

int32_t g_num_files = 0;
char *files[MAX_NUM_MODULES] = {0};

typedef long (*set_affinity_fn)(pid_t, const struct cpumask *);
set_affinity_fn set_cpu_affinity;

/* ========================================================================== */
/* Misc Device                                                                */
/* ========================================================================== */

static int
dev_open(struct inode *inode, struct file *file)
{
    DEBUG("dev_open succeeded\n");
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
    DEBUG("dev_release succeeded\n");
    return 0;
}

int32_t
ioctl_add_module(char *file)
{
    char *buf;
    int32_t ret;

    if (g_num_files >= MAX_NUM_MODULES)
    {
        ALERT("IOCTL_ADD_MODULE: too many modules have been loaded\n");
        return BF_IOCTL_ERROR_ADD_MODULE_FAILED;
    }

    /*
     * On Linux, we are not given a size for the IOCTL. Appearently
     * it is common practice to seperate this information into two
     * different IOCTLs, which is what we do here. This however means
     * that we have to store state, so userspace has to be careful
     * to send these IOCTLs in the correct order.
     *
     * Linux also does not copy userspace memory for use, so we need
     * to do this ourselves. As a result, we alloc memory for the
     * buffer that userspace is providing us so that we can copy this
     * memory from userspace as needed.
     */

    buf = platform_alloc(g_module_length);
    if (buf == NULL)
    {
        ALERT("IOCTL_ADD_MODULE: failed to allocate memory for the module\n");
        return BF_IOCTL_ERROR_ADD_MODULE_FAILED;
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
    g_num_files++;

    DEBUG("IOCTL_ADD_MODULE: succeeded\n");
    return BF_IOCTL_SUCCESS;

failed:

    vfree(buf);

    DEBUG("IOCTL_ADD_MODULE: failed\n");
    return BF_IOCTL_ERROR_ADD_MODULE_FAILED;
}

int32_t
ioctl_add_module_length(int32_t len)
{
    g_module_length = len;

    DEBUG("IOCTL_ADD_MODULE_LENGTH: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

int32_t
ioctl_start_vmm(void)
{
    int ret;

    ret = common_start_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_START_VMM: failed to start vmm: %d\n", ret);
        return ret;
    }

    DEBUG("IOCTL_START_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

int32_t
ioctl_stop_vmm(void)
{
    int i;
    int ret;

    ret = common_stop_vmm();
    if (ret != BF_SUCCESS)
        ALERT("IOCTL_STOP_VMM: failed to stop vmm: %d\n", ret);

    for (i = 0; i < g_num_files; i++)
        platform_free(files[i]);

    g_num_files = 0;

    DEBUG("IOCTL_STOP_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

int32_t
ioctl_dump_vmm(void)
{
    int ret;

    ret = common_dump_vmm();
    if (ret != BF_SUCCESS)
        ALERT("IOCTL_DUMP_VMM: failed to dump vmm: %d\n", ret);

    DEBUG("IOCTL_DUMP_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
dev_unlocked_ioctl(struct file *file,
                   unsigned int cmd,
                   unsigned long arg)
{
    const struct cpumask *cpu0 = cpumask_of(0);
    set_cpu_affinity(current->pid, cpu0);

    switch (cmd)
    {
        case IOCTL_ADD_MODULE:
            return ioctl_add_module((char *)arg);

        case IOCTL_ADD_MODULE_LENGTH:
            return ioctl_add_module_length((int32_t)arg);

        case IOCTL_START_VMM:
            return ioctl_start_vmm();

        case IOCTL_STOP_VMM:
            return ioctl_stop_vmm();

        case IOCTL_DUMP_VMM:
            return ioctl_dump_vmm();

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
    "bareflank",
    &fops
};

/* ========================================================================== */
/* Entry                                                                      */
/* ========================================================================== */

int
dev_init(void)
{
    int ret;

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
    common_fini();
    misc_deregister(&bareflank_dev);

    DEBUG("dev_exit succeeded\n");
    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
