/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#define INITGUID
#pragma warning(disable:4242) // conversions are okay (or not)!
#include <ntddk.h>
#include <wdf.h>
#include <driver_entry_interface.h>

#include "device.h"
#include "queue.h"
#include "trace.h"

EXTERN_C_START

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD bareflankEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL bareflankEvtIoDeviceControl;
EVT_WDF_DEVICE_FILE_CREATE bareflankEvtDeviceFileCreate;
EVT_WDF_FILE_CLOSE bareflankEvtDeviceFileClose;
EVT_WDF_OBJECT_CONTEXT_CLEANUP bareflankEvtDriverContextCleanup;

EXTERN_C_END
