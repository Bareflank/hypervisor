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

/**
 * @file bfvmcallinterface.h
 */

#ifndef VMCALL_INTERFACE_H
#define VMCALL_INTERFACE_H

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * VMCall Magic Number
 *
 * Defines a magic number that can be defined by the user to uniquely identify
 * both the version of the user as well as the VMM. Note that this value will
 * change with each release of Bareflank, but should probably be manually set
 * when creating production code.
 */
#ifndef VMCALL_MAGIC_NUMBER
#define VMCALL_MAGIC_NUMBER 0xB045EACDACD52E22
#endif

/**
 * VMCall Version
 *
 * Define the version of this VMCall ABI. Note that unlike the magic number,
 * this number only changes when this file changes.
 */
#define VMCALL_VERSION 1

/**
 * VMCall Opcode
 *
 * Defines the vmcall being made. Note that these are generic vmcall opcodes,
 * and they made be used to create actual commands to the hypervisor. For
 * example, the registers vmcall could contain user defined instructions
 * while the data vmcall could also contain JSON formatted instructions.
 *
 * Each opcode is defined below. Note that these might change as part of
 * an updated. It's up to the user to ensure that versions match correctly.
 */
enum vmcall_opcode {
    /*
     * Versions
     *
     * Returns version information from the hypervisor which can be used by
     * users of the vmcall interface to ensure that their code is compatible
     * with the VMM.
     *
     * @note: indexes 0x0000000000000000 -> 0x7FFFFFFFFFFFFFFF are reserved
     *     for Bareflank. The remaining indexes may be used by custom
     *     extensions for version information
     *
     * In:
     * r0 = VMCALL_VERSIONS
     * r1 = VMCALL_MAGIC_NUMBER
     * r2 = index
     *
     * Out (index == VMCALL_VERSION_PROTOCOL):
     * r1 = 0 == success, error code otherwise
     * r2 = index
     * r3 = VMCALL_VERSION
     *
     * Out (index == VMCALL_VERSION_BAREFLANK):
     * r1 = 0 == success, error code otherwise
     * r2 = index
     * r3 = BAREFLANK_VERSION_MAJOR
     * r4 = BAREFLANK_VERSION_MINOR
     * r5 = BAREFLANK_VERSION_PATCH
     *
     * Out (index == VMCALL_VERSION_USER):
     * r1 = 0 == success, error code otherwise
     * r2 = index
     * r3 = USER_VERSION_MAJOR
     * r4 = USER_VERSION_MINOR
     * r5 = USER_VERSION_PATCH
     *
     * Out (index > 0x8000000000000000): User-defined
     */
    VMCALL_VERSIONS = 1,

    /*
     * Raw Registers
     *
     * Provides a means to send to the VMM, raw register values, and
     * return raw register values. This is a wrapper around your basic vmcall,
     * consuming the reserved registers in the process for ABI compatibility
     *
     * In:
     * r0 = VMCALL_REGISTERS
     * r1 = VMCALL_MAGIC_NUMBER
     * r2 = xxx
     * ...
     * r31 = xxx
     *
     * Out:
     * r1 = 0 == success, error code otherwise
     * r2 = xxx
     * ...
     * r31 = xxx
     */
    VMCALL_REGISTERS = 2,

    /*
     * Data
     *
     * Provides a means to send and receive binary data (page sharing). With
     * this vmcall, an in and out buffer are provided. The VMM will map in
     * both buffers, perform whatever operation it should, and then unmap the
     * buffers. The type field must be provided for the input buffer, and it
     * defines what type of data is being provided. The VMM will return data
     * in the output buffer, and set the output type based on whatever
     * operation it performed. The size is in bytes, but the VMM will map
     * complete pages. If the size of the buffer is not a multiple of a page,
     * the VMM will have access to data outside the bounds of the buffer
     * (which may be fine depending on the use case). The uuid field is provided
     * as a means to identify the data being sent / received. Specifically,
     * this field can be paired with the registers vmcall to ensure that
     * consecutive vmcalls have the proper data. For example, if an operation
     * takes more than one vmcall to perform, and software on the CPU is
     * threaded, the uuid field provides the VMM with a means to handle when
     * more than one vmcall becomes interlaced. Note that the uuid field is
     * optional. out_size contains the max size of the output buffer that
     * is provided, but the VMM must set out_size to the actual number of
     * bytes that it is sending back, which likely will not be the same as
     * the output buffer going in is likely the "max" sized buffer, while the
     * actual contents being written back are likely smaller.
     *
     * In:
     * r0 = VMCALL_DATA
     * r1 = VMCALL_MAGIC_NUMBER
     * r2 = uuid1 (bits 0 -> 63)
     * r3 = uuid2 (bits 64 -> 127)
     * r4 = in_type (vmcall_data_type)
     * r5 = in_addr (addr of virtually contiguous buffer)
     * r6 = in_size (size of virtually contiguous buffer)
     * r7 = out_type (vmcall_data_type)
     * r8 = out_addr (addr of virtually contiguous buffer)
     * r9 = out_size (size of virtually contiguous buffer)
     *
     * Out:
     * r1 = 0 == success, error code otherwise
     */
    VMCALL_DATA = 3,

    /*
     * Event
     *
     * This vmcall is used to signal and event (basically a virtual interrupt)
     * Note that this takes a different path so it's faster than using
     * VMCALL_REGISTERS as that call does more register copying. Also note
     * that we provide for a success / failure on the event and it's up to the
     * VMM extensions to decide if an event can actually fail.
     *
     * In:
     * r0 = VMCALL_EVENT
     * r1 = VMCALL_MAGIC_NUMBER
     * r2 = index
     *
     * Out:
     * r1 = 0 == success, error code otherwise
     */
    VMCALL_EVENT = 4,

    /*
     * Start
     *
     * This vmcall is used to run "start" code while the hypervisor is running.
     * This vmcall should not be used by software and can only be used one
     * by the bfdriver common.c
     *
     * In:
     * r0 = VMCALL_START
     * r1 = VMCALL_MAGIC_NUMBER
     *
     * Out:
     * r1 = 0 == success, error code otherwise
     */
    VMCALL_START = 5,

    /*
     * Stop
     *
     * This vmcall is used to run "stop" code while the hypervisor is running.
     * This vmcall should not be used by software and can only be used one
     * by the bfdriver common.c
     *
     * In:
     * r0 = VMCALL_STOP
     * r1 = VMCALL_MAGIC_NUMBER
     *
     * Out:
     * r1 = 0 == success, error code otherwise
     */
    VMCALL_STOP = 6,

    /*
     * Unit Test
     *
     * This vmcall is used to unit test software inside the VMM. For example,
     * for Bareflank to ensure that supported portions of libc++ actually work
     * inside the VMM, unit testing must be performed in the VMM itself. This
     * vmcall does that.
     *
     * @note: indexes 0x0000000000000000 -> 0x7FFFFFFFFFFFFFFF are reserved
     *     for Bareflank. The remaining indexes may be used by custom
     *     extensions for their own unit tests
     *
     * In:
     * r0 = VMCALL_UNITTEST
     * r1 = VMCALL_MAGIC_NUMBER
     * r2 = index
     *
     * Out:
     * r1 = 0 == success, error code otherwise
     */
    VMCALL_UNITTEST = 10,
};

/**
 * VMCall Versions
 *
 * Defines the different version indexes that are officially supported
 * by Bareflank. Others may be used by the user as defined by the protocol
 *
 * @note: indexes 0x0000000000000000 -> 0x7FFFFFFFFFFFFFFF are reserved
 *     for Bareflank. The remaining indexes may be used by custom
 *     extensions to define their own version info
*/
enum vmcall_versions {
    VMCALL_VERSION_PROTOCOL = 0,
    VMCALL_VERSION_BAREFLANK = 1,
    VMCALL_VERSION_USER = 10,
};

/**
 * VMCall Data Type
 *
 * Defines the different data types for data vmcall.
 *
 * @note: types 0x0000000000000000 -> 0x7FFFFFFFFFFFFFFF are reserved
 *     for Bareflank. The remaining types may be used by custom
 *     extensions to define their own data types
 */
enum vmcall_data_type {
    VMCALL_DATA_NONE = 0,
    VMCALL_DATA_STRING_UNFORMATTED = 1,
    VMCALL_DATA_STRING_JSON = 2,
    VMCALL_DATA_BINARY_UNFORMATTED = 10,
};

/**
 * @struct vmcall_registers_t
 *
 * VMCall Registers
 *
 * Defines a structure that stores each register. The register names are
 * generic so that they can be used by different CPU architectures.
 *
 * Intel: (unused: rsp, rbp, rdi)
 * r0 = rax
 * r1 = rdx
 * r2 = rcx
 * r3 = rbx
 * r4 = rsi
 * r5 = r8
 * r6 = r9
 * r7 = r10
 * r8 = r11
 * r9 = r12
 * r10 = r13
 * r11 = r14
 * r12 = r15
 * r13 = undefined
 * ...
 * r31 = undefined
 *
 * ARM:
 * N/A
 *
 * @var vmcall_registers_t::r00
 *      register 0
 * @var vmcall_registers_t::r01
 *      register 1
 * @var vmcall_registers_t::r02
 *      register 2
 * @var vmcall_registers_t::r03
 *      register 3
 * @var vmcall_registers_t::r04
 *      register 4
 * @var vmcall_registers_t::r05
 *      register 5
 * @var vmcall_registers_t::r06
 *      register 6
 * @var vmcall_registers_t::r07
 *      register 7
 * @var vmcall_registers_t::r08
 *      register 8
 * @var vmcall_registers_t::r09
 *      register 9
 * @var vmcall_registers_t::r10
 *      register 10
 * @var vmcall_registers_t::r11
 *      register 11
 * @var vmcall_registers_t::r12
 *      register 12
 * @var vmcall_registers_t::r13
 *      register 13
 * @var vmcall_registers_t::r14
 *      register 14
 * @var vmcall_registers_t::r15
 *      register 15
 */
struct vmcall_registers_t {
    uintptr_t r00;
    uintptr_t r01;
    uintptr_t r02;
    uintptr_t r03;
    uintptr_t r04;
    uintptr_t r05;
    uintptr_t r06;
    uintptr_t r07;
    uintptr_t r08;
    uintptr_t r09;
    uintptr_t r10;
    uintptr_t r11;
    uintptr_t r12;
    uintptr_t r13;
    uintptr_t r14;
    uintptr_t r15;
};

/**
 * VMCall
 *
 * Performs a VMCall to the hypervisor. Note that this VMCall has to touch
 * all of the registers so its slower than using VMCall event if you only
 * need a single index
 *
 * @param regs register state
 */
void vmcall(struct vmcall_registers_t *regs);

/**
 * VMCall Event
 *
 * Performs a VMCall event to the hypervisor. Note that this VMCall only
 * touches a couple of registers so it's faster than the generic vmcall, but
 * in return only supports r00, r01 and r02.
 *
 * @param regs register state
 */
void vmcall_event(struct vmcall_registers_t *regs);

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
