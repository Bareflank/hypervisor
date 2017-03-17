/*
 * Bareflank Hypervisor
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <debug.h>
#include <driver.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

struct pmodule_t
{
    char *data;
    int64_t size;
};

int64_t g_num_pmodules = 0;
struct pmodule_t pmodules[MAX_NUM_MODULES] = { 0 };

uint64_t g_cpuid = 0;
uint64_t g_vcpuid = 0;

/* -------------------------------------------------------------------------- */
/* IO Functions                                                               */
/* -------------------------------------------------------------------------- */

static int64_t
ioctl_add_module(char *file, int64_t len)
{
    char *buf;
    int64_t ret;

    if (g_num_pmodules >= MAX_NUM_MODULES)
    {
        ALERT("IOCTL_ADD_MODULE: too many modules have been loaded\n");
        return BF_IOCTL_FAILURE;
    }

    buf = platform_alloc_rwe(len);
    if (buf == NULL)
    {
        ALERT("IOCTL_ADD_MODULE: failed to allocate memory for the module\n");
        return BF_IOCTL_FAILURE;
    }

    platform_memset(buf, 0, len);
    platform_memcpy(buf, file, len);

    ret = common_add_module(buf, len);
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_ADD_MODULE: common_add_module failed: %p - %s\n",
              (void *)ret, ec_to_str(ret));
        goto failed;
    }

    pmodules[g_num_pmodules].data = buf;
    pmodules[g_num_pmodules].size = len;

    g_num_pmodules++;

    DEBUG("IOCTL_ADD_MODULE: succeeded\n");
    return BF_IOCTL_SUCCESS;

failed:

    platform_free_rwe(buf, len);

    ALERT("IOCTL_ADD_MODULE: failed\n");
    return BF_IOCTL_FAILURE;
}

static int64_t
ioctl_unload_vmm(void)
{
    int64_t i;
    int64_t ret;
    int64_t status = BF_IOCTL_SUCCESS;

    ret = common_unload_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_UNLOAD_VMM: common_unload_vmm failed: %p - %s\n",
              (void *)ret, ec_to_str(ret));
        status = BF_IOCTL_FAILURE;
    }

    for (i = 0; i < g_num_pmodules; i++)
        platform_free_rwe(pmodules[i].data, pmodules[i].size);

    g_num_pmodules = 0;
    platform_memset(&pmodules, 0, sizeof(pmodules));

    if (status == BF_IOCTL_SUCCESS)
        DEBUG("IOCTL_UNLOAD_VMM: succeeded\n");

    return status;
}

static int64_t
ioctl_load_vmm(void)
{
    int64_t ret;

    ret = common_load_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_LOAD_VMM: ioctl_load_vmm failed: %p - %s\n",
              (void *)ret, ec_to_str(ret));
        goto failure;
    }

    DEBUG("IOCTL_LOAD_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;

failure:

    ioctl_unload_vmm();
    return BF_IOCTL_FAILURE;
}

static int64_t
ioctl_stop_vmm(void)
{
    int64_t ret;
    int64_t status = BF_IOCTL_SUCCESS;

    ret = common_stop_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_STOP_VMM: ioctl_stop_vmm failed: %p - %s\n",
              (void *)ret, ec_to_str(ret));
        status = BF_IOCTL_FAILURE;
    }

    if (status == BF_IOCTL_SUCCESS)
        DEBUG("IOCTL_STOP_VMM: succeeded\n");

    return status;
}

static int64_t
ioctl_start_vmm(void)
{
    int64_t ret;

    ret = common_start_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_START_VMM: ioctl_start_vmm failed: %p - %s\n",
              (void *)ret, ec_to_str(ret));
        goto failure;
    }

    DEBUG("IOCTL_START_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;

failure:

    ioctl_stop_vmm();
    return BF_IOCTL_FAILURE;
}

static int64_t
ioctl_dump_vmm(struct debug_ring_resources_t *user_drr)
{
    int64_t ret;
    struct debug_ring_resources_t *drr = 0;

    ret = common_dump_vmm(&drr, g_vcpuid);
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_DUMP_VMM: common_dump_vmm failed: %p - %s\n",
              (void *)ret, ec_to_str(ret));
        return BF_IOCTL_FAILURE;
    }

    platform_memcpy(user_drr, drr, sizeof(struct debug_ring_resources_t));

    DEBUG("IOCTL_DUMP_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static int64_t
ioctl_vmm_status(int64_t *status)
{
    int64_t vmm_status = common_vmm_status();

    if (status == 0)
    {
        ALERT("IOCTL_VMM_STATUS: common_vmm_status failed: NULL\n");
        return BF_IOCTL_FAILURE;
    }

    *status = vmm_status;

    DEBUG("IOCTL_VMM_STATUS: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static int64_t
ioctl_set_cpuid(uint64_t *cpuid)
{
    if (cpuid == 0)
    {
        ALERT("IOCTL_SET_CPUID: failed with len == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    g_cpuid = *cpuid;

    DEBUG("IOCTL_SET_CPUID: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static int64_t
ioctl_set_vcpuid(uint64_t *vcpuid)
{
    if (vcpuid == 0)
    {
        ALERT("IOCTL_SET_VCPUID: failed with len == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    g_vcpuid = *vcpuid;

    DEBUG("IOCTL_SET_VCPUID: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static int64_t
ioctl_vmcall(struct vmcall_registers_t *inregs, struct vmcall_registers_t *outregs)
{
    int64_t ret;

    ret = common_vmcall(inregs, g_cpuid);
    if (ret != 0)
    {
        ALERT("IOCTL_VMCALL: common_vmcall failed: %p - %s\n", \
              (void *)ret, ec_to_str(ret));
        return BF_IOCTL_FAILURE;
    }

    RtlCopyMemory(outregs, inregs, sizeof(struct vmcall_registers_t));
    return BF_IOCTL_SUCCESS;
}

NTSTATUS
bareflankQueueInitialize(
    _In_ WDFDEVICE Device
)
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchParallel
    );

    queueConfig.EvtIoStop = bareflankEvtIoStop;
    queueConfig.EvtIoDeviceControl = bareflankEvtIoDeviceControl;

    status = WdfIoQueueCreate(Device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status))
        return status;

    if (common_init() != BF_SUCCESS)
    {
        ALERT("common_init failed\n");
        return STATUS_ACCESS_DENIED;
    }

    DEBUG("bareflankQueueInitialize: success\n");
    return STATUS_SUCCESS;
}

VOID
bareflankEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    PVOID in = 0;
    PVOID out = 0;
    size_t in_size = 0;
    size_t out_size = 0;

    int64_t ret = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Queue);

    if (InputBufferLength != 0)
    {
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &in, &in_size);

        if (!NT_SUCCESS(status))
            goto FAILURE;
    }

    if (OutputBufferLength != 0)
    {
        status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &out, &out_size);

        if (!NT_SUCCESS(status))
            goto FAILURE;
    }

    switch (IoControlCode)
    {
        case IOCTL_ADD_MODULE:
            ret = ioctl_add_module((char *)in, (int64_t)in_size);
            break;

        case IOCTL_LOAD_VMM:
            ret = ioctl_load_vmm();
            break;

        case IOCTL_UNLOAD_VMM:
            ret = ioctl_unload_vmm();
            break;

        case IOCTL_START_VMM:
            ret = ioctl_start_vmm();
            break;

        case IOCTL_STOP_VMM:
            ret = ioctl_stop_vmm();
            break;

        case IOCTL_DUMP_VMM:
            ret = ioctl_dump_vmm((struct debug_ring_resources_t *)out);
            break;

        case IOCTL_VMM_STATUS:
            ret = ioctl_vmm_status((int64_t *)out);
            break;

        case IOCTL_SET_CPUID:
            ret = ioctl_set_cpuid((uint64_t *)in);
            break;

        case IOCTL_SET_VCPUID:
            ret = ioctl_set_vcpuid((uint64_t *)in);
            break;

        case IOCTL_VMCALL:
            ret = ioctl_vmcall((struct vmcall_registers_t *)in, (struct vmcall_registers_t *)out);
            break;

        default:
            goto FAILURE;
    }

    if (OutputBufferLength != 0)
        WdfRequestSetInformation(Request, out_size);

    if (ret != BF_IOCTL_SUCCESS)
        goto FAILURE;

    WdfRequestComplete(Request, STATUS_SUCCESS);
    return;

FAILURE:

    WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
    return;
}

VOID
bareflankEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
)
{
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(ActionFlags);

    WdfRequestComplete(Request, STATUS_SUCCESS);
    return;
}
