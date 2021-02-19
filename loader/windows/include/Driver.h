/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

// clang-format off

/// NOTE:
/// - The windows includes that we use here need to remain in this order.
///   Otherwise the code will not compile.
///

#include <initguid.h>
#include <ntddk.h>
#include <wdf.h>

#include "device.h"
#include "queue.h"
#include "trace.h"

// clang-format on

EXTERN_C_START

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD loaderEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP loaderEvtDriverContextCleanup;

EXTERN_C_END
