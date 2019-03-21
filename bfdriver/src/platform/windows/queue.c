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

#include <driver.h>

/* -------------------------------------------------------------------------- */
/* Status                                                                     */
/* -------------------------------------------------------------------------- */

int g_status = 0;
FAST_MUTEX g_status_mutex;

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

static uint64_t g_vcpuid = 0;

struct pmodule_t {
    char *data;
    int64_t size;
};

static uint64_t g_num_pmodules = 0;
static struct pmodule_t pmodules[MAX_NUM_MODULES] = { 0 };

/* -------------------------------------------------------------------------- */
/* Misc Device                                                                */
/* -------------------------------------------------------------------------- */

static int64_t
ioctl_add_module(const char *file, int64_t len)
{
    char *buf;
    int64_t ret;

    if (g_num_pmodules >= MAX_NUM_MODULES) {
        BFALERT("IOCTL_ADD_MODULE: too many modules have been loaded\n");
        return BF_IOCTL_FAILURE;
    }

    buf = platform_alloc_rw(len);
    if (buf == NULL) {
        BFALERT("IOCTL_ADD_MODULE: failed to allocate memory for the module\n");
        return BF_IOCTL_FAILURE;
    }

    RtlCopyMemory(buf, file, len);

    ret = common_add_module(buf, len);
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_ADD_MODULE: common_add_module failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto IOCTL_FAILURE;
    }

    pmodules[g_num_pmodules].data = buf;
    pmodules[g_num_pmodules].size = len;

    g_num_pmodules++;

    return BF_IOCTL_SUCCESS;

IOCTL_FAILURE:

    platform_free_rw(buf, len);
    return BF_IOCTL_FAILURE;
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
    ExAcquireFastMutex(&g_status_mutex);

    ret = common_stop_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_STOP_VMM: common_stop_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto IOCTL_FAILURE;
    }

    g_status = STATUS_STOPPED;

    ExReleaseFastMutex(&g_status_mutex);
    return BF_IOCTL_SUCCESS;

IOCTL_FAILURE:

    ExReleaseFastMutex(&g_status_mutex);
    return BF_IOCTL_FAILURE;
}

static long
ioctl_start_vmm(void)
{
    int64_t ret;
    ExAcquireFastMutex(&g_status_mutex);

    ret = common_start_vmm();
    if (ret != BF_SUCCESS) {
        BFALERT("IOCTL_START_VMM: common_start_vmm failed: %p - %s\n", (void *)ret, ec_to_str(ret));
        goto IOCTL_FAILURE;
    }

    g_status = STATUS_RUNNING;

    ExReleaseFastMutex(&g_status_mutex);
    return BF_IOCTL_SUCCESS;

IOCTL_FAILURE:

    common_stop_vmm();

    ExReleaseFastMutex(&g_status_mutex);
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

    RtlCopyMemory(user_drr, drr, sizeof(struct debug_ring_resources_t));
    return BF_IOCTL_SUCCESS;
}

static long
ioctl_vmm_status(int64_t *status)
{
    int64_t vmm_status = common_vmm_status();

    if (status == 0) {
        BFALERT("IOCTL_VMM_STATUS: common_vmm_status failed: NULL\n");
        return BF_IOCTL_FAILURE;
    }

    *status = vmm_status;
    return BF_IOCTL_SUCCESS;
}

static long
ioctl_set_vcpuid(uint64_t *vcpuid)
{
    if (vcpuid == 0) {
        BFALERT("IOCTL_SET_VCPUID: failed with vcpuid == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    g_vcpuid = *vcpuid;
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
    if (!NT_SUCCESS(status)) {
        BFALERT("WdfIoQueueCreate failed\n");
        goto INIT_FAILURE;
    }

    if (common_init() != 0) {
        BFALERT("common_init failed\n");
        goto INIT_FAILURE;
    }

    g_status = STATUS_STOPPED;
    ExInitializeFastMutex(&g_status_mutex);

    return STATUS_SUCCESS;

INIT_FAILURE:

    return STATUS_UNSUCCESSFUL;
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

    if (InputBufferLength != 0) {
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &in, &in_size);

        if (!NT_SUCCESS(status)) {
            goto IOCTL_FAILURE;
        }
    }

    if (OutputBufferLength != 0) {
        status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &out, &out_size);

        if (!NT_SUCCESS(status)) {
            goto IOCTL_FAILURE;
        }
    }

    switch (IoControlCode) {
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

        case IOCTL_SET_VCPUID:
            ret = ioctl_set_vcpuid((uint64_t *)in);
            break;

        default:
            goto IOCTL_FAILURE;
    }

    if (OutputBufferLength != 0) {
        WdfRequestSetInformation(Request, out_size);
    }

    if (ret != BF_IOCTL_SUCCESS) {
        goto IOCTL_FAILURE;
    }

    WdfRequestComplete(Request, STATUS_SUCCESS);
    return;

IOCTL_FAILURE:

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
