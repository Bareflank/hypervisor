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

#ifndef THREAD_CONTEXT
#define THREAD_CONTEXT

#include <types.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Get Thread Context CPUID
 *
 * @return returns the cpuid from the current thread context
 */
uint64_t thread_context_cpuid(void);

/**
 * Get Thread Context TLS Pointer
 *
 * @return returns the pointer to the TLS data for the current thread context
 */
uint64_t thread_context_tlsptr(void);

/**
 * Thread Context
 *
 * On the top of every stack pointer sits one of these structures, which is
 * used to identify thread specific information. For more information on
 * how this works, please see the following post:
 *
 * https://github.com/Bareflank/hypervisor/issues/213
 *
 * Note: If this struct changes, assembly code in the misc module will
 * likely have to change as well since we don't have a clean way to bridge
 * between C and NASM
 */
struct thread_context_t
{
    uint64_t cpuid;
    uint64_t tlsptr;
    uint64_t reserved1;
    uint64_t reserved2;
};

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
