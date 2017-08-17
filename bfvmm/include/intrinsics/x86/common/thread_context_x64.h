//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef THREAD_CONTEXT_X64_H
#define THREAD_CONTEXT_X64_H

#include <cstdint>
#include <bfconstants.h>
#include <bfthreadcontext.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_INTRINSICS
#ifdef SHARED_INTRINSICS
#define EXPORT_INTRINSICS EXPORT_SYM
#else
#define EXPORT_INTRINSICS IMPORT_SYM
#endif
#else
#define EXPORT_INTRINSICS
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

extern "C" EXPORT_INTRINSICS uint64_t thread_context_cpuid(void);
extern "C" EXPORT_INTRINSICS uint64_t thread_context_tlsptr(void);

// -----------------------------------------------------------------------------
// Setup Stack
// -----------------------------------------------------------------------------

inline auto
setup_stack(void *stack)
{
    auto stack_uintptr = reinterpret_cast<uintptr_t>(stack);

    auto stack_top = stack_uintptr + (STACK_SIZE * 2);
    stack_top = (stack_top & ~(STACK_SIZE - 1)) - 1;
    stack_uintptr = stack_top - sizeof(thread_context_t) - 1;

    auto tc = reinterpret_cast<thread_context_t *>(stack_top - sizeof(thread_context_t));
    tc->cpuid = thread_context_cpuid();
    tc->tlsptr = thread_context_tlsptr();

    return stack_uintptr;
}

#endif
