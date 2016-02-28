
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

#include <iostream>
#include <vcpu/vcpu_manager.h>
#include <exit_handler/exit_handler_dispatch.h>

// -----------------------------------------------------------------------------
// C++ Implementation
// -----------------------------------------------------------------------------

void
exit_handler_trampoline(void)
{
    // Hardcode vcpuid to zero for now
    g_vcm->dispatch(0);
}

// -----------------------------------------------------------------------------
// C Implementation
// -----------------------------------------------------------------------------

// The C implementation is needed bcause the actual exit handler entry point is
// in assembly, which doesn't have access to the mangled C++ ABI. So to keep
// things simple, the assembly jumps into C code first, which is then handed
// off to C++ from there.

extern "C" void
exit_handler(void)
{
    exit_handler_trampoline();
}

extern "C" void *
exit_handler_stack(void)
{
    static char stack[0x2000] = {0};

    // Note that we return the stack pointer, plus the size of the stack,
    // minus one because the stack grows down and thus, the starting point
    // of the stack is actually the end of it.

    return &stack[0x1999];
}
