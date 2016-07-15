/*++

Module Name:

    queue.c

Abstract:

    This file contains the queue entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "queue.tmh"
#include <common.h>
#include <platform.h>
#include <debug.h>
#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, bareflankQueueInitialize)
#endif

int64_t g_module_length = 0;
int64_t g_num_files = 0;

uint64_t g_vcpuid = 0;

char *files[MAX_NUM_MODULES] = { 0 };
int64_t file_size[MAX_NUM_MODULES] = { 0 };
/* Private IOCTL methods, setting up for common calls */

static long
ioctl_add_module(char *file)
{
    int64_t ret;
    char *buf;

    if (g_num_files >= MAX_NUM_MODULES)
    {
        ALERT("IOCTL_ADD_MODULE: too many modules have been loaded\n");
        return BF_IOCTL_FAILURE;
    }

    buf = platform_alloc_rwe(g_module_length);
    if (buf == NULL)
    {
        ALERT("IOCTL_ADD_MODULE: failed to allocate memory for the module\n");
        return BF_IOCTL_FAILURE;
    }
    DEBUG("g_module_length: %d\r\n", g_module_length);
    platform_memcpy(buf, file, g_module_length);

    ret = common_add_module(buf, g_module_length);
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_ADD_MODULE: failed to add module\n");
        goto failed;
    }

    files[g_num_files] = buf;
    file_size[g_num_files] = g_module_length;
    g_num_files++;

    DEBUG("IOCTL_ADD_MODULE: succeeded\n");
    return BF_IOCTL_SUCCESS;

failed:

    platform_free_rwe(buf, 0);

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

    DEBUG("g_module_length ----- %d\r\n", *len);

    DEBUG("IOCTL_ADD_MODULE_LENGTH: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
ioctl_unload_vmm(void)
{
    int64_t i;
    int64_t ret;
    long status = BF_IOCTL_SUCCESS;

    ret = common_unload_vmm();
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_UNLOAD_VMM: failed to unload vmm: %d\n", ret);
        status = BF_IOCTL_FAILURE;
    }

    for (i = 0; i < g_num_files; i++)
        platform_free_rwe(files[i], file_size[i]);

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
    int64_t ret;
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
    int64_t ret;

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
    int64_t ret;
    struct debug_ring_resources_t *drr = 0;

    ret = common_dump_vmm(&drr, g_vcpuid);
    if (ret != BF_SUCCESS)
    {
        ALERT("IOCTL_DUMP_VMM: failed to dump vmm: %d\n", ret);
        return BF_IOCTL_FAILURE;
    }

    platform_memcpy(user_drr, drr, sizeof(struct debug_ring_resources_t));

    DEBUG("IOCTL_DUMP_VMM: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

static long
ioctl_vmm_status(int64_t *status)
{
    int64_t vmm_status = common_vmm_status();

    if (status == 0)
    {
        ALERT("IOCTL_VMM_STATUS: failed with status == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    //platform_memcpy(status, &vmm_status, sizeof(int64_t));
    *status = vmm_status;
    DEBUG("IOCTL_VMM_STATUS: succeeded %"PRId64"\n", vmm_status);
    return BF_IOCTL_SUCCESS;
}



NTSTATUS
bareflankQueueInitialize(
    _In_ WDFDEVICE Device
)
/*++

Routine Description:


     The I/O dispatch callbacks for the frameworks device object
     are configured in this function.

     A single default I/O Queue is configured for parallel request
     processing, and a driver context memory allocation is created
     to hold our structure QUEUE_CONTEXT.

Arguments:

    Device - Handle to a framework device object.

Return Value:

    VOID

--*/
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG    queueConfig;

    PAGED_CODE();

    //
    // Configure a default queue so that requests that are not
    // configure-fowarded using WdfDeviceConfigureRequestDispatching to goto
    // other queues get dispatched here.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchParallel
    );

    queueConfig.EvtIoDeviceControl = bareflankEvtIoDeviceControl;
    queueConfig.EvtIoStop = bareflankEvtIoStop;

    status = WdfIoQueueCreate(
                 Device,
                 &queueConfig,
                 WDF_NO_OBJECT_ATTRIBUTES,
                 &queue
             );

    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfIoQueueCreate failed %!STATUS!", status);
        return status;
    }

    return status;
}

VOID
bareflankEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
/*++

Routine Description:

    This event is invoked when the framework receives IRP_MJ_DEVICE_CONTROL request.

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    OutputBufferLength - Size of the output buffer in bytes

    InputBufferLength - Size of the input buffer in bytes

    IoControlCode - I/O control code.

Return Value:

    VOID

--*/
{
    uint32_t rc = 0;
    PVOID in = 0, out = 0;
    size_t in_size = 0, out_size = 0;

    TraceEvents(TRACE_LEVEL_INFORMATION,
                TRACE_QUEUE,
                "%!FUNC! Queue 0x%p, Request 0x%p OutputBufferLength %d InputBufferLength %d IoControlCode %d",
                Queue, Request, (int) OutputBufferLength, (int) InputBufferLength, IoControlCode);

    if (InputBufferLength != 0)
    {
        TRACE();
        rc = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &in, &in_size);

        DEBUG("insize: %d\r\n", in_size);

        if (!NT_SUCCESS(rc))
        {
            TRACE();
            goto FAIL_IOCTL;
        }
    }

    if (OutputBufferLength != 0)
    {
        TRACE();
        rc = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &out, &out_size);

        if (!NT_SUCCESS(rc))
        {
            TRACE();
            goto FAIL_IOCTL;
        }
    }

    switch (IoControlCode)
    {
        case IOCTL_ADD_MODULE:
            rc = ioctl_add_module((char *)in);
            break;
        case IOCTL_ADD_MODULE_LENGTH:
            rc = ioctl_add_module_length((int64_t *)in);
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
            rc = ioctl_dump_vmm((struct debug_ring_resources_t *)out);
            break;
        case IOCTL_VMM_STATUS:
            rc = ioctl_vmm_status((int64_t *)out);
            break;
        default:
            rc = (uint32_t) STATUS_INVALID_PARAMETER;
            break;
    }

    if (OutputBufferLength != 0)
    {
        WdfRequestSetInformation(Request, out_size);
    }

    WdfRequestComplete(Request, rc);

    return;

FAIL_IOCTL:
    WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);

    return;
}

VOID
bareflankEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
)
/*++

Routine Description:

    This event is invoked for a power-managed queue before the device leaves the working state (D0).

Arguments:

    Queue -  Handle to the framework queue object that is associated with the
             I/O request.

    Request - Handle to a framework request object.

    ActionFlags - A bitwise OR of one or more WDF_REQUEST_STOP_ACTION_FLAGS-typed flags
                  that identify the reason that the callback function is being called
                  and whether the request is cancelable.

Return Value:

    VOID

--*/
{
    TraceEvents(TRACE_LEVEL_INFORMATION,
                TRACE_QUEUE,
                "%!FUNC! Queue 0x%p, Request 0x%p ActionFlags %d",
                Queue, Request, ActionFlags);

    //
    // In most cases, the EvtIoStop callback function completes, cancels, or postpones
    // further processing of the I/O request.
    //
    // Typically, the driver uses the following rules:
    //
    // - If the driver owns the I/O request, it calls WdfRequestUnmarkCancelable
    //   (if the request is cancelable) and either calls WdfRequestStopAcknowledge
    //   with a Requeue value of TRUE, or it calls WdfRequestComplete with a
    //   completion status value of STATUS_SUCCESS or STATUS_CANCELLED.
    //
    //   Before it can call these methods safely, the driver must make sure that
    //   its implementation of EvtIoStop has exclusive access to the request.
    //
    //   In order to do that, the driver must synchronize access to the request
    //   to prevent other threads from manipulating the request concurrently.
    //   The synchronization method you choose will depend on your driver's design.
    //
    //   For example, if the request is held in a shared context, the EvtIoStop callback
    //   might acquire an internal driver lock, take the request from the shared context,
    //   and then release the lock. At this point, the EvtIoStop callback owns the request
    //   and can safely complete or requeue the request.
    //
    // - If the driver has forwarded the I/O request to an I/O target, it either calls
    //   WdfRequestCancelSentRequest to attempt to cancel the request, or it postpones
    //   further processing of the request and calls WdfRequestStopAcknowledge with
    //   a Requeue value of FALSE.
    //
    // A driver might choose to take no action in EvtIoStop for requests that are
    // guaranteed to complete in a small amount of time.
    //
    // In this case, the framework waits until the specified request is complete
    // before moving the device (or system) to a lower power state or removing the device.
    // Potentially, this inaction can prevent a system from entering its hibernation state
    // or another low system power state. In extreme cases, it can cause the system
    // to crash with bugcheck code 9F.
    //

    return;
}

