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

#ifndef BFDRIVERINTERFACE_H
#define BFDRIVERINTERFACE_H

#include <bftypes.h>
#include <bfdebugringinterface.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Common                                                                     */
/* -------------------------------------------------------------------------- */

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

#define IOCTL_ADD_MODULE_LENGTH_CMD 0x801
#define IOCTL_ADD_MODULE_CMD 0x802
#define IOCTL_LOAD_VMM_CMD 0x803
#define IOCTL_UNLOAD_VMM_CMD 0x804
#define IOCTL_START_VMM_CMD 0x805
#define IOCTL_STOP_VMM_CMD 0x806
#define IOCTL_DUMP_VMM_CMD 0x807
#define IOCTL_VMM_STATUS_CMD 0x808
#define IOCTL_SET_VCPUID_CMD 0x80A

/* -------------------------------------------------------------------------- */
/* Linux Interfaces                                                           */
/* -------------------------------------------------------------------------- */

#ifdef __linux__

#define IOCTL_ADD_MODULE_LENGTH _IOW(BAREFLANK_MAJOR, IOCTL_ADD_MODULE_LENGTH_CMD, uint64_t *)
#define IOCTL_ADD_MODULE _IOW(BAREFLANK_MAJOR, IOCTL_ADD_MODULE_CMD, char *)
#define IOCTL_LOAD_VMM _IO(BAREFLANK_MAJOR, IOCTL_LOAD_VMM_CMD)
#define IOCTL_UNLOAD_VMM _IO(BAREFLANK_MAJOR, IOCTL_UNLOAD_VMM_CMD)
#define IOCTL_START_VMM _IO(BAREFLANK_MAJOR, IOCTL_START_VMM_CMD)
#define IOCTL_STOP_VMM _IO(BAREFLANK_MAJOR, IOCTL_STOP_VMM_CMD)
#define IOCTL_DUMP_VMM _IOR(BAREFLANK_MAJOR, IOCTL_DUMP_VMM_CMD, struct debug_ring_resources_t *)
#define IOCTL_VMM_STATUS _IOR(BAREFLANK_MAJOR, IOCTL_VMM_STATUS_CMD, int64_t *)
#define IOCTL_SET_VCPUID _IOW(BAREFLANK_MAJOR, IOCTL_SET_VCPUID_CMD, uint64_t *)

#endif

/* -------------------------------------------------------------------------- */
/* Windows Interfaces                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__)

#include <initguid.h>

DEFINE_GUID(
    GUID_DEVINTERFACE_bareflank,
    0x1d9c9218,
    0x3c88,
    0x4b81,
    0x8e,
    0x81,
    0xb4,
    0x62,
    0x2a,
    0x4d,
    0xcb,
    0x44);

#define IOCTL_ADD_MODULE CTL_CODE(0xF00D, IOCTL_ADD_MODULE_CMD, METHOD_IN_DIRECT, FILE_WRITE_DATA)
#define IOCTL_LOAD_VMM CTL_CODE(0xF00D, IOCTL_LOAD_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_UNLOAD_VMM CTL_CODE(0xF00D, IOCTL_UNLOAD_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_START_VMM CTL_CODE(0xF00D, IOCTL_START_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_STOP_VMM CTL_CODE(0xF00D, IOCTL_STOP_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_DUMP_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_DUMP_VMM_CMD, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_VMM_STATUS CTL_CODE(0xF00D, IOCTL_VMM_STATUS_CMD, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_SET_VCPUID CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_SET_VCPUID_CMD, METHOD_IN_DIRECT, FILE_WRITE_DATA)

#endif

#ifdef __cplusplus
}
#endif

#endif
