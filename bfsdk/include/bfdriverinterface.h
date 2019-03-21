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

#ifndef BAREFLANK_DEVICETYPE
#define BAREFLANK_DEVICETYPE 0xF00D
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
#define IOCTL_VMCALL_CMD 0x810

/**
 * @struct ioctl_vmcall_args_t
 *
 * Stores the general registers for a vmcall
 *
 * @var ioctl_vmcall_args_t::reg1
 *     general register #1
 * @var ioctl_vmcall_args_t::reg2
 *     general register #2
 * @var ioctl_vmcall_args_t::reg3
 *     general register #3
 * @var ioctl_vmcall_args_t::reg4
 *     general register #4
 */
struct ioctl_vmcall_args_t {
    uint64_t reg1;
    uint64_t reg2;
    uint64_t reg3;
    uint64_t reg4;
};

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
#define IOCTL_VMCALL _IOWR(BAREFLANK_MAJOR, IOCTL_VMCALL_CMD, struct ioctl_vmcall_args_t *)

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

#define IOCTL_ADD_MODULE CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_ADD_MODULE_CMD, METHOD_IN_DIRECT, FILE_WRITE_DATA)
#define IOCTL_LOAD_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_LOAD_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_UNLOAD_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_UNLOAD_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_START_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_START_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_STOP_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_STOP_VMM_CMD, METHOD_BUFFERED, 0)
#define IOCTL_DUMP_VMM CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_DUMP_VMM_CMD, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define IOCTL_VMM_STATUS CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_VMM_STATUS_CMD, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_SET_VCPUID CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_SET_VCPUID_CMD, METHOD_IN_DIRECT, FILE_WRITE_DATA)
#define IOCTL_VMCALL CTL_CODE(BAREFLANK_DEVICETYPE, IOCTL_VMCALL_CMD, METHOD_IN_DIRECT, FILE_READ_WRITE_DATA)

#endif

#ifdef __cplusplus
}
#endif

#endif
