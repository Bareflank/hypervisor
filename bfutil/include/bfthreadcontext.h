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
setup_stack(void *stack, uint64_t cpuid)
{
    struct thread_context_t *tc;
    uint64_t stack_int = bfrcast(uint64_t, stack);

    uint64_t stack_top = stack_int + (STACK_SIZE * 2);
    stack_top = (stack_top & ~(STACK_SIZE - 1)) - 1;
    stack_int = stack_top - sizeof(struct thread_context_t) - 1;

    tc = bfrcast(struct thread_context_t *, stack_top - sizeof(struct thread_context_t));
    tc->cpuid = cpuid;
    tc->tlsptr = thread_context_tlsptr();

    return stack_int;
}

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
