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

#ifndef KERNEL
#include <stdint.h>
#else
#include <types.h>
#endif

#include <debug_ring_interface.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/* Common                                                                     */
/* ========================================================================== */

/**
 * Driver Error Codes
 */
#define BF_IOCTL_SUCCESS 0
#define BF_IOCTL_FAILURE -10000

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

/* ========================================================================== */
/* Linux Interfaces                                                           */
/* ========================================================================== */

#ifdef __linux__

#ifndef BAREFLANK_NAME
#define BAREFLANK_NAME "bareflank"
#endif

#ifndef BAREFLANK_MAJOR
#define BAREFLANK_MAJOR 150
#endif

/**
 * Add Module Length
 *
 * This IOCTL tells the driver entry point what the size of the module to
 * be loaded will be. Note that this cannot be called while the vmm is running.
 *
 * @param arg length of the module to be added in bytes
 */
#define IOCTL_ADD_MODULE_LENGTH _IOW(BAREFLANK_MAJOR, 101, int64_t *)

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
#define IOCTL_ADD_MODULE _IOW(BAREFLANK_MAJOR, 100, char *)

/**
 * Load VMM
 *
 * This IOCTL tells the driver entry to load the virtual machine monitor. Note
 * that the VMM must be in an unloaded state, and all of the modules must be
 * added using IOCTL_ADD_MODULE
 */
#define IOCTL_LOAD_VMM _IO(BAREFLANK_MAJOR, 200)

/**
 * Unload VMM
 *
 * This IOCTL tells the driver entry to unload the virtual machine monitor.
 * Note that the VMM must be in a loaded state, but not running. This IOCTL
 * will unload the VMM, and remove any modules that were added via
 * IOCTL_ADD_MODULE. If the VMM is to be loaded again, the modules must be
 * added first.
 */
#define IOCTL_UNLOAD_VMM _IO(BAREFLANK_MAJOR, 300)

/**
 * Start VMM
 *
 * This IOCTL tells the driver entry to start the virtual machine monitor. Note
 * that this cannot be called while the vmm is running. All of the modules
 * should have already been loaded prior to calling this IOCTL using
 * IOCTL_ADD_MODULE
 */
#define IOCTL_START_VMM _IO(BAREFLANK_MAJOR, 400)

/**
 * Stop VMM
 *
 * This IOCTL tells the driver entry to stop the virtual machine monitor. Note
 * that this cannot be called while the vmm is not running.
 */
#define IOCTL_STOP_VMM _IO(BAREFLANK_MAJOR, 500)

/**
 * Dump VMM
 *
 * This IOCTL tells the driver entry to dump the contents of the shared debug
 * ring withing the VMM. Note that the VMM must be loaded prior to calling
 * this IOCTL using IOCTL_LOAD_VMM
 */
#define IOCTL_DUMP_VMM _IOR(BAREFLANK_MAJOR, 600, struct debug_ring_resources_t *)

/**
 * VMM Status
 *
 * This queries the driver for it's current state. This can be called at any
 * time.
 */
#define IOCTL_VMM_STATUS _IOR(BAREFLANK_MAJOR, 700, int64_t *)

#endif

/* ========================================================================== */
/* Windows Interfaces                                                         */
/* ========================================================================== */

#ifdef _WIN32
#endif

/* ========================================================================== */
/* OSX Interfaces                                                             */
/* ========================================================================== */

#ifdef __APPLE__
#endif

#ifdef __cplusplus
}
#endif

#endif
