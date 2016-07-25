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

#ifndef DRIVER_ENTRY_INTERFACE_H
#define DRIVER_ENTRY_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Common                                                                     */
/* -------------------------------------------------------------------------- */

/*
 * Driver Entry State Machine
 *
 *  The driver entry has three major states that it could end up in. When the
 *  driver entry is unloaded, it means that the VMM has not been placed in
 *  memory. The loaded state means that the VMM is in memory, and relocated.
 *  In this state, symbol lookups are possible, and thus things like the VMM
 *  dump comand work. The running state means that the VMM is actually running.
 *  The goal of the state machine is to ensure that the driver keeps track of
 *  the state of the VMM, and handles its transition properly.
 */
#define VMM_UNLOADED 10
#define VMM_LOADED 11
#define VMM_RUNNING 12
#define VMM_CORRUPT 100

#ifndef BAREFLANK_NAME
#define BAREFLANK_NAME "bareflank"
#endif

#ifndef BAREFLANK_MAJOR
#define BAREFLANK_MAJOR 150
#endif

#ifndef BAREFLANK_DEVICETYPE
#define BAREFLANK_DEVICETYPE 0xf00d
#endif

#define IOCTL_ADD_MODULE_LENGTH_CMD 101
#define IOCTL_ADD_MODULE_CMD 100
#define IOCTL_LOAD_VMM_CMD 200
#define IOCTL_UNLOAD_VMM_CMD 300
#define IOCTL_START_VMM_CMD 400
#define IOCTL_STOP_VMM_CMD 500
#define IOCTL_DUMP_VMM_CMD 600
#define IOCTL_VMM_STATUS_CMD 700
#define IOCTL_SET_VCPUID_CMD 800

#include <debug_ring_interface.h>

/* -------------------------------------------------------------------------- */
/* Linux Interfaces                                                           */
/* -------------------------------------------------------------------------- */

#ifdef __linux__

#ifndef KERNEL
#include <stdint.h>
#else
#include <types.h>
#endif

/**
 * Add Module Length
 *
 * This IOCTL tells the driver entry point what the size of the module to
 * be loaded will be. Note that this cannot be called while the vmm is running.
 *
 * @param arg length of the module to be added in bytes
 */
#define IOCTL_ADD_MODULE_LENGTH _IOW(BAREFLANK_MAJOR, IOCTL_ADD_MODULE_LENGTH_CMD, int64_t *)

/**
 * Add Module
 *
 * This IOCTL instructs the driver entry point to add a module. Note that this
 * cannot be called while the vmm is running. Prior to calling this IOCTL,
 * you must call IOCTL_ADD_MODULE_LENGTH, to inform the driver entry point what
 * the size of the module is.
 *
 * @param arg character buffer containing the module to add
 * @return
 */
#define IOCTL_ADD_MODULE _IOW(BAREFLANK_MAJOR, IOCTL_ADD_MODULE_CMD, char *)

/**
 * Load VMM
 *
 * This IOCTL tells the driver entry to load the virtual machine monitor. Note
 * that the VMM must be in an unloaded state, and all of the modules must be
 * added using IOCTL_ADD_MODULE
 */
#define IOCTL_LOAD_VMM _IO(BAREFLANK_MAJOR, IOCTL_LOAD_VMM_CMD)

/**
 * Unload VMM
 *
 * This IOCTL tells the driver entry to unload the virtual machine monitor.
 * Note that the VMM must be in a loaded state, but not running. This IOCTL
 * will unload the VMM, and remove any modules that were added via
 * IOCTL_ADD_MODULE. If the VMM is to be loaded again, the modules must be
 * added first.
 */
#define IOCTL_UNLOAD_VMM _IO(BAREFLANK_MAJOR, IOCTL_UNLOAD_VMM_CMD)

/**
 * Start VMM
 *
 * This IOCTL tells the driver entry to start the virtual machine monitor. Note
 * that this cannot be called while the vmm is running. All of the modules
 * should have already been loaded prior to calling this IOCTL using
 * IOCTL_ADD_MODULE
 */
#define IOCTL_START_VMM _IO(BAREFLANK_MAJOR, IOCTL_START_VMM_CMD)

/**
 * Stop VMM
 *
 * This IOCTL tells the driver entry to stop the virtual machine monitor. Note
 * that this cannot be called while the vmm is not running.
 */
#define IOCTL_STOP_VMM _IO(BAREFLANK_MAJOR, IOCTL_STOP_VMM_CMD)

/**
 * Dump VMM
 *
 * This IOCTL tells the driver entry to dump the contents of the shared debug
 * ring withing the VMM. Note that the VMM must be loaded prior to calling
 * this IOCTL using IOCTL_LOAD_VMM
 */
#define IOCTL_DUMP_VMM _IOR(BAREFLANK_MAJOR, IOCTL_DUMP_VMM_CMD, struct debug_ring_resources_t *)

/**
 * VMM Status
 *
 * This queries the driver for it's current state. This can be called at any
 * time.
 */
#define IOCTL_VMM_STATUS _IOR(BAREFLANK_MAJOR, IOCTL_VMM_STATUS_CMD, int64_t *)

/**
 * Set VCPUID
 *
 * This IOCTL tells the driver entry point what vcpuid the userspace
 * application would like to focus on.
 *
 * @param arg the vcpuid to focus commands on
 */
#define IOCTL_SET_VCPUID _IOW(BAREFLANK_MAJOR, IOCTL_SET_VCPUID_CMD, uint64_t *)

#endif

/* -------------------------------------------------------------------------- */
/* Windows Interfaces                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__)

#ifdef KERNEL
#include <ntddk.h>
#else
#include <windows.h>
#include <initguid.h>
#endif

DEFINE_GUID(GUID_DEVINTERFACE_bareflank,
            0x1d9c9218, 0x3c88, 0x4b81, 0x8e, 0x81, 0xb4, 0x62, 0x2a, 0x4d, 0xcb, 0x44);

/**
 * Add Module Length (*** DEPRECATED ***)
 *
 * This IOCTL tells the driver entry point what the size of the module to
 * be loaded will be. Note that this cannot be called while the vmm is running.
 *
 * @param arg length of the module to be added in bytes
 */
#define IOCTL_ADD_MODULE_LENGTH CTL_CODE(BAREFLANK_DEVICETYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

/**
 * Add Module
 *
 * This IOCTL instructs the driver entry point to add a module. Note that this
 * cannot be called while the vmm is running. Prior to calling this IOCTL,
 * you must call IOCTL_ADD_MODULE_LENGTH, to inform the driver entry point what
 * the size of the module is.
 *
 * @param arg character buffer containing the module to add
 * @return
 */
#define IOCTL_ADD_MODULE CTL_CODE(BAREFLANK_DEVICETYPE, 0x901, METHOD_IN_DIRECT, FILE_WRITE_DATA)

/**
 * Load VMM
 *
 * This IOCTL tells the driver entry to load the virtual machine monitor. Note
 * that the VMM must be in an unloaded state, and all of the modules must be
 * added using IOCTL_ADD_MODULE
 */
#define IOCTL_LOAD_VMM CTL_CODE(BAREFLANK_DEVICETYPE, 0xA01, METHOD_BUFFERED, FILE_WRITE_DATA)

/**
 * Unload VMM
 *
 * This IOCTL tells the driver entry to unload the virtual machine monitor.
 * Note that the VMM must be in a loaded state, but not running. This IOCTL
 * will unload the VMM, and remove any modules that were added via
 * IOCTL_ADD_MODULE. If the VMM is to be loaded again, the modules must be
 * added first.
 */
#define IOCTL_UNLOAD_VMM CTL_CODE(BAREFLANK_DEVICETYPE, 0xB00, METHOD_BUFFERED, FILE_WRITE_DATA)

/**
 * Start VMM
 *
 * This IOCTL tells the driver entry to start the virtual machine monitor. Note
 * that this cannot be called while the vmm is running. All of the modules
 * should have already been loaded prior to calling this IOCTL using
 * IOCTL_ADD_MODULE
 */
#define IOCTL_START_VMM CTL_CODE(BAREFLANK_DEVICETYPE, 0xC00, METHOD_BUFFERED, FILE_WRITE_DATA)

/**
 * Stop VMM
 *
 * This IOCTL tells the driver entry to stop the virtual machine monitor. Note
 * that this cannot be called while the vmm is not running.
 */
#define IOCTL_STOP_VMM CTL_CODE(BAREFLANK_DEVICETYPE, 0xD00, METHOD_BUFFERED, FILE_WRITE_DATA)

/**
 * Dump VMM
 *
 * This IOCTL tells the driver entry to dump the contents of the shared debug
 * ring withing the VMM. Note that the VMM must be loaded prior to calling
 * this IOCTL using IOCTL_LOAD_VMM
 */
#define IOCTL_DUMP_VMM CTL_CODE(BAREFLANK_DEVICETYPE, 0xE00, METHOD_OUT_DIRECT, FILE_READ_DATA)

/**
 * VMM Status
 *
 * This queries the driver for it's current state. This can be called at any
 * time.
 */
#define IOCTL_VMM_STATUS CTL_CODE(BAREFLANK_DEVICETYPE, 0xF00, METHOD_BUFFERED, FILE_READ_DATA)

/**
 * Set VCPUID
 *
 * This IOCTL tells the driver entry point what vcpuid the userspace
 * application would like to focus on.
 *
 * @param arg the vcpuid to focus commands on
 */
#define IOCTL_SET_VCPUID CTL_CODE(BAREFLANK_DEVICETYPE, 0xF80, METHOD_IN_DIRECT, FILE_WRITE_DATA)

#endif

/* -------------------------------------------------------------------------- */
/* OSX Interfaces                                                             */
/* -------------------------------------------------------------------------- */

#ifdef __APPLE__
#include <stdint.h>

typedef struct bf_ioctl
{
    uint32_t command;
    uint32_t size;
    void *addr;
} bf_ioctl_t;

#define IOCTL_ADD_MODULE_LENGTH IOCTL_ADD_MODULE_LENGTH_CMD
#define IOCTL_ADD_MODULE IOCTL_ADD_MODULE_CMD
#define IOCTL_LOAD_VMM IOCTL_LOAD_VMM_CMD
#define IOCTL_UNLOAD_VMM IOCTL_UNLOAD_VMM_CMD
#define IOCTL_START_VMM IOCTL_START_VMM_CMD
#define IOCTL_STOP_VMM IOCTL_STOP_VMM_CMD
#define IOCTL_DUMP_VMM IOCTL_DUMP_VMM_CMD
#define IOCTL_VMM_STATUS IOCTL_VMM_STATUS_CMD
#define IOCTL_SET_VCPUID IOCTL_SET_VCPUID_CMD

#endif

#ifdef __cplusplus
}
#endif

#endif
