/*
 * Bareflank Hypervisor
 * Copyright (C) 2015 Assured Information Security, Inc.
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

#define INITGUID

#include <ntddk.h>
#include <wdf.h>

#include <queue.h>
#include <device.h>

#include <common.h>

#include <bfdebug.h>
#include <bfplatform.h>
#include <bfdriverinterface.h>

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD bareflankEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP bareflankEvtDriverContextCleanup;
EVT_WDF_DEVICE_D0_ENTRY bareflankEvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT bareflankEvtDeviceD0Exit;

EXTERN_C_END
