/*++

Module Name:

    queue.c

Abstract:

    This file contains the queue entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

// clang-format off

/// NOTE:
/// - The windows includes that we use here need to remain in this order.
///   Otherwise the code will not compile.
///

#include "../include/driver.h"
#include "queue.tmh"

#include <debug.h>
#include <dump_vmm.h>
#include <dump_vmm_args_t.h>
#include <start_vmm.h>
#include <start_vmm_args_t.h>
#include <stop_vmm.h>
#include <stop_vmm_args_t.h>
#include <loader_platform_interface.h>

// clang-format on

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, loaderQueueInitialize)
#endif

NTSTATUS
loaderQueueInitialize(_In_ WDFDEVICE Device)
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
    WDF_IO_QUEUE_CONFIG queueConfig;

    PAGED_CODE();

    //
    // Configure a default queue so that requests that are not
    // configure-fowarded using WdfDeviceConfigureRequestDispatching to goto
    // other queues get dispatched here.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);

    queueConfig.EvtIoDeviceControl = loaderEvtIoDeviceControl;
    queueConfig.EvtIoStop = loaderEvtIoStop;

    status = WdfIoQueueCreate(Device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfIoQueueCreate failed %!STATUS!", status);
        return status;
    }

    return status;
}

VOID
loaderEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode)
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
    PVOID in = 0;
    PVOID out = 0;
    size_t in_size = 0;
    size_t out_size = 0;

    NTSTATUS status;

    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_QUEUE,
        "%!FUNC! Queue 0x%p, Request 0x%p OutputBufferLength %d "
        "InputBufferLength %d IoControlCode %d",
        Queue,
        Request,
        (int)OutputBufferLength,
        (int)InputBufferLength,
        IoControlCode);

    if (InputBufferLength != 0) {
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &in, &in_size);

        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
            return;
        }
    }

    if (OutputBufferLength != 0) {
        status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &out, &out_size);

        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
            return;
        }

        WdfRequestSetInformation(Request, out_size);
    }

    switch (IoControlCode) {
        case LOADER_START_VMM: {
            if (start_vmm((struct start_vmm_args_t const *)in)) {
                bferror("start_vmm failed");
                WdfRequestComplete(Request, STATUS_UNSUCCESSFUL);
                return;
            }
            break;
        }
        case LOADER_STOP_VMM: {
            if (stop_vmm((struct stop_vmm_args_t const *)in)) {
                bferror("stop_vmm failed");
                WdfRequestComplete(Request, STATUS_UNSUCCESSFUL);
                return;
            }
            break;
        }
        case LOADER_DUMP_VMM: {
            if (dump_vmm((struct dump_vmm_args_t const *)out)) {
                bferror("dump_vmm failed");
                WdfRequestComplete(Request, STATUS_UNSUCCESSFUL);
                return;
            }
            break;
        }
        default: {
            bferror_x64("invalid ioctl cmd", IoControlCode);
            WdfRequestComplete(Request, STATUS_ACCESS_DENIED);
            return;
        }
    }

    WdfRequestComplete(Request, STATUS_SUCCESS);
    return;
}

VOID
loaderEvtIoStop(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request, _In_ ULONG ActionFlags)
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
    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_QUEUE,
        "%!FUNC! Queue 0x%p, Request 0x%p ActionFlags %d",
        Queue,
        Request,
        ActionFlags);

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

    WdfRequestComplete(Request, STATUS_SUCCESS);
    return;
}
