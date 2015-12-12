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

#ifndef EXIT_HANDLER
#define EXIT_HANDLER

/// Exit Handler
///
/// When a Virtual Machine exits do to an instruction that the VMM must
/// emulate, this function is the first symbol to be executed by the VMM.
/// In other words, this is the VMM's exit handler entry point.
///
void exit_handler();

/// Exit Handler Stack
///
/// The exit handler must be given a stack as it will be executing in it's
/// own context while a virtual machine is running, and thus cannot shre the
/// same stack.
///
char *exit_handler_stack();

#endif
