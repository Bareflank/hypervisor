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
#include <entry/entry_factory.h>

// =============================================================================
// Global
// =============================================================================

#define EXIT_HANDLER_STACK_SIZE 1024

char stack[EXIT_HANDLER_STACK_SIZE] = {0};

// =============================================================================
// Entry Functions
// =============================================================================

void
exit_handler()
{
}

char *
exit_handler_stack()
{
    // Note that we return the stack pointer, plus the size of the stack,
    // minus one because the stack grows down and thus, the starting point
    // of the stack is actually the end of it.

    return (char *)((uint64_t)stack + EXIT_HANDLER_STACK_SIZE);
}
