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

/* ========================================================================== */
/* Common                                                                     */
/* ========================================================================== */

#define BF_IOCTL_SUCCESS 0
#define BF_IOCTL_ERROR_ADD_MODULE_FAILED -10001
#define BF_IOCTL_ERROR_ADD_MODULE_LENGTH_FAILED -10002
#define BF_IOCTL_ERROR_START_VMM_FAILED -10003
#define BF_IOCTL_ERROR_STOP_VMM_FAILED -10004

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
 * Add Module
 *
 * This IOCTL instructs the driver entry point to add a module. Note that this
 * cannot be called while the vmm is running. Prior to calling this IOCTL,
 * you must call IOCTL_ADD_MODULE_LENGTH, to inform the driver entry point what
 * the size of the module is.
 *
 * @param arg character buffer containing the module to add
 */
#define IOCTL_ADD_MODULE _IOR(BAREFLANK_MAJOR, 100, char *)

/**
 * Add Module Length
 *
 * This IOCTL tells the driver entry point what the size of the module to
 * be loaded will be. Note that this cannot be called while the vmm is running.
 *
 * @param arg length of the module to be added in bytes
 */
#define IOCTL_ADD_MODULE_LENGTH _IOR(BAREFLANK_MAJOR, 101, char *)

/**
 * Start VMM
 *
 * This IOCTL tells the driver entry to start the virtual machine monitor. Note
 * that this cannot be called while the vmm is running. All of the modeuls
 * should have already been loaded prior to calling this IOCTL using
 * IOCTL_ADD_MODULE
 */
#define IOCTL_START_VMM _IOR(BAREFLANK_MAJOR, 200, char *)

/**
 * Stop VMM
 *
 * This IOCTL tells the driver entry to stop the virtual machine monitor. Note
 * that this cannot be called while the vmm is not running.
 */
#define IOCTL_STOP_VMM _IOR(BAREFLANK_MAJOR, 300, char *)

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

#endif
