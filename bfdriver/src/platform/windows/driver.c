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

extern int g_status;
extern FAST_MUTEX g_status_mutex;

/* -------------------------------------------------------------------------- */
/* Driver                                                                     */
/* -------------------------------------------------------------------------- */

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = bareflankEvtDriverContextCleanup;

    WDF_DRIVER_CONFIG_INIT(&config, bareflankEvtDeviceAdd);

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
bareflankEvtDeviceAdd(
    _In_    WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    NTSTATUS status;
    WDF_PNPPOWER_EVENT_CALLBACKS  pnpPowerCallbacks;

    UNREFERENCED_PARAMETER(Driver);

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDeviceD0Entry = bareflankEvtDeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0Exit = bareflankEvtDeviceD0Exit;

    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    status = bareflankCreateDevice(DeviceInit);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
bareflankEvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    ExAcquireFastMutex(&g_status_mutex);

    common_fini();
    g_status = STATUS_STOPPED;

    ExReleaseFastMutex(&g_status_mutex);
}

static int g_sleeping = 0;

NTSTATUS
bareflankEvtDeviceD0Entry(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(PreviousState);

    ExAcquireFastMutex(&g_status_mutex);

    if (g_status != STATUS_SUSPEND) {
        ExReleaseFastMutex(&g_status_mutex);
        return STATUS_SUCCESS;
    }

    if (common_start_vmm() != BF_SUCCESS) {

        common_fini();
        g_status = STATUS_STOPPED;

        ExReleaseFastMutex(&g_status_mutex);
        return STATUS_UNSUCCESSFUL;
    }

    g_status = STATUS_RUNNING;

    ExReleaseFastMutex(&g_status_mutex);
    return STATUS_SUCCESS;
}

NTSTATUS
bareflankEvtDeviceD0Exit(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(TargetState);

    ExAcquireFastMutex(&g_status_mutex);

    if (g_status != STATUS_RUNNING) {
        ExReleaseFastMutex(&g_status_mutex);
        return STATUS_SUCCESS;
    }

    if (common_stop_vmm() != BF_SUCCESS) {

        common_fini();
        g_status = STATUS_STOPPED;

        ExReleaseFastMutex(&g_status_mutex);
        return STATUS_UNSUCCESSFUL;
    }

    g_status = STATUS_SUSPEND;

    ExReleaseFastMutex(&g_status_mutex);
    return STATUS_SUCCESS;
}
