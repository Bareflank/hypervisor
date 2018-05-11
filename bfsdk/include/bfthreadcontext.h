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

/**
 * @file bfthreadcontext.h
 */

#ifndef BFTHREADCONTEXT
#define BFTHREADCONTEXT

#include <bftypes.h>
#include <bfconstants.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return CPUID
 *
 * @return returns the CPUID for the currently executing thread
 */
uint64_t thread_context_cpuid(void);

/**
 * Return TLS data
 *
 * @return returns the TLS data for the currently executing thread
 */
uint64_t *thread_context_tlsptr(void);

/**
 * @struct thread_context_t
 *
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
 *
 * @var thread_context_t::cpuid
 *      the cpuid of the thread
 * @var thread_context_t::tlsptr
 *      the TLS pointer of the thread
 * @var thread_context_t::reserved1
 *      reserved
 * @var thread_context_t::reserved2
 *      reserved
 */
struct thread_context_t {
    uint64_t cpuid;
    uint64_t *tlsptr;
    uint64_t reserved1;
    uint64_t reserved2;
};

/**
 * Setup Stack
 *
 * The following function sets up the stack to match the algorithm defined
 * in the following issue:
 *
 * https://github.com/Bareflank/hypervisor/issues/213
 *
 * @param stack the stack pointer
 * @return the stack pointer (in interger form)
 */
static inline uint64_t
setup_stack(void *stack)
{
    struct thread_context_t *tc;
    uint64_t stack_int = bfrcast(uint64_t, stack);

    uint64_t stack_top = stack_int + (STACK_SIZE * 2);
    stack_top = (stack_top & ~(STACK_SIZE - 1)) - 1;
    stack_int = stack_top - sizeof(struct thread_context_t) - 1;

    tc = bfrcast(struct thread_context_t *, stack_top - sizeof(struct thread_context_t));
    tc->cpuid = thread_context_cpuid();
    tc->tlsptr = thread_context_tlsptr();

    return stack_int;
}

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
