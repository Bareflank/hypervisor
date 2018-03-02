#include <debug.h>
#include <common.h>
#include <platform.h>
#include <constants.h>
#include <driver_entry_interface.h>
#include "entry.h"

//extern void xnu_thread_bind(unsigned int);
//extern void xnu_thread_unbind(void);

//////////
OSDefineMetaClassAndStructors(org_bareflank_osx, IOUserClient)

// -----------------------------------------------------------------------------
// Global
// -----------------------------------------------------------------------------

#define ALERT(...) IOLog(__VA_ARGS__)
#define DEBUG(...) IOLog(__VA_ARGS__)

int64_t g_module_length = 0;

int64_t g_num_files = 0;
char *files[MAX_NUM_MODULES] = {0};
int64_t files_sizes[MAX_NUM_MODULES] = {0};

// -----------------------------------------------------------------------------
// IOKit Base Functions

bool org_bareflank_osx::start(IOService *provider)
{
    bool success;

    IOLog("bareflank: start\n");

    success = IOUserClient::start(provider);

    if (success)
    {
        IOLog("bareflank: regserv now!\n");

        registerService();
    }
    else
    {
        IOLog("bareflank: no regserv :(\n");
    }

    return success;
}

void org_bareflank_osx::stop(IOService *provider)
{
    IOLog("bareflank: stop\n");

    return IOUserClient::stop(provider);
}

bool org_bareflank_osx::init(OSDictionary *dictionary)
{
    IOLog("bareflank: init\n");

    int64_t ret;

    if ((ret = common_init()) != 0)
    {
        ALERT("common_init failed\n");
        return ret;
    }

    DEBUG("dev_init succeeded\n");

    return IOUserClient::init(dictionary);
}

void org_bareflank_osx::free(void)
{
    common_fini();

    IOLog("bareflank: free\n");

    IOUserClient::free();
}

IOReturn org_bareflank_osx::externalMethod(uint32_t selector, IOExternalMethodArguments *arguments, IOExternalMethodDispatch *dispatch, OSObject *target, void *reference)
{
    IOReturn rc;

    // Executre Method: Command
    if (selector == 1)
    {
        bf_ioctl_t *in = (bf_ioctl_t *)arguments->structureInput;
        bf_ioctl_t *out = (bf_ioctl_t *)arguments->structureOutput;

        uint32_t in_size = arguments->structureInputSize;
        uint32_t out_size = sizeof(*out);

        // Dispatch the command routine.
        rc = methodCommand(in, out, in_size, &out_size);

        return rc;
    }

    return IOUserClient::externalMethod(selector, arguments, dispatch, target, reference);
}

static long
ioctl_add_module(char *file)
{
    char *buf;
    int64_t ret;

    if (g_num_files >= MAX_NUM_MODULES)
    {
        ALERT("IOCTL_ADD_MODULE: too many modules have been loaded\n");
        return BF_IOCTL_FAILURE;
    }

    buf = (char *)platform_alloc(g_module_length);
    if (buf == NULL)
    {
        ALERT("IOCTL_ADD_MODULE: failed to allocate memory for the module\n");
        return BF_IOCTL_FAILURE;
    }

    ALERT("address to copy from %p size: 0x%" PRId64 "\n", file, g_module_length);

    ret = copyin((user_addr_t)file, (void *)buf, g_module_length);

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
    files_sizes[g_num_files] = g_module_length;

    g_num_files++;

    DEBUG("IOCTL_ADD_MODULE: succeeded\n");
    return BF_IOCTL_SUCCESS;

failed:

    platform_free(buf, g_module_length);

    DEBUG("IOCTL_ADD_MODULE: failed\n");
    return BF_IOCTL_FAILURE;
}

static long
ioctl_add_module_length(int64_t *len)
{
    if (len == 0)
    {
        ALERT("IOCTL_ADD_MODULE_LENGTH: failed with len == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    g_module_length = *len;

    ALERT("g_module_length: %lld\n", g_module_length);

    DEBUG("IOCTL_ADD_MODULE_LENGTH: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
ioctl_unload_vmm(void)
{
    int i;
    int64_t ret;
    long status = BF_IOCTL_SUCCESS;

    ret = common_unload_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_UNLOAD_VMM: failed to unload vmm: %lld\n", ret);
        status = BF_IOCTL_FAILURE;
    }

    for (i = 0; i < g_num_files; i++)
        platform_free(files[i], files_sizes[i]);

    g_num_files = 0;

    if (status == BF_IOCTL_SUCCESS)
        DEBUG("IOCTL_UNLOAD_VMM: succeeded\n");

    return status;
}

static long
ioctl_load_vmm(void)
{
    int64_t ret;

    ret = common_load_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_LOAD_VMM: failed to load vmm: %lld\n", ret);
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
    int64_t ret;
    long status = BF_IOCTL_SUCCESS;

    ret = common_stop_vmm();

    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_STOP_VMM: failed to stop vmm: %lld\n", ret);
        status = BF_IOCTL_FAILURE;
    }

    if (status == BF_IOCTL_SUCCESS)
        DEBUG("IOCTL_STOP_VMM: succeeded\n");

    return status;
}

static long
ioctl_start_vmm(void)
{
    int64_t ret;

    ret = common_start_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_START_VMM: failed to start vmm: %lld\n", ret);
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
    int64_t ret;

    ret = common_dump_vmm(&user_drr);
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_DUMP_VMM: failed to dump vmm: %lld\n", ret);
        return BF_IOCTL_FAILURE;
    }

    DEBUG("IOCTL_DUMP_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
ioctl_vmm_status(int64_t *status)
{
    if (status == 0)
    {
        ALERT("IOCTL_VMM_STATUS: failed with status == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    *status = common_vmm_status();

    DEBUG("IOCTL_VMM_STATUS: succeeded\n");
    return BF_IOCTL_SUCCESS;
}


IOReturn org_bareflank_osx::methodCommand(bf_ioctl_t *in_ioctl, bf_ioctl_t *out_ioctl, uint32_t inStructSize, uint32_t *outStructSize)
{
    //    xnu_thread_bind(0);
    //    thread_block(THREAD_CONTINUE_NULL);

    // If this code is called, the IOCTL was successful. From here, we need to figure
    // out which command was sent, and then execute that command.

    IOLog("Got to ioctl 0x%08X\n", in_ioctl->command);
    uint32_t rc = 0;

    switch (in_ioctl->command)
    {
        case IOCTL_ADD_MODULE:
            rc = ioctl_add_module((char *)(in_ioctl->addr));
            break;
        case IOCTL_ADD_MODULE_LENGTH:
            rc = ioctl_add_module_length((int64_t *)in_ioctl->addr);
            break;
        case IOCTL_LOAD_VMM:
            rc = ioctl_load_vmm();
            break;
        case IOCTL_UNLOAD_VMM:
            rc = ioctl_unload_vmm();
            break;
        case IOCTL_START_VMM:
            rc = ioctl_start_vmm();
            break;
        case IOCTL_STOP_VMM:
            rc = ioctl_stop_vmm();
            break;
        case IOCTL_DUMP_VMM:
            rc = ioctl_dump_vmm((struct debug_ring_resources_t *)in_ioctl->addr);
            break;
        case IOCTL_VMM_STATUS:
            rc = ioctl_vmm_status((int64_t *)in_ioctl->addr);
            break;
        default:
            return (IOReturn) - EINVAL;
    }

    out_ioctl->command = rc;
    out_ioctl->addr = 0;
    out_ioctl->size = 0;

    // Done.
    return kIOReturnSuccess;
}
