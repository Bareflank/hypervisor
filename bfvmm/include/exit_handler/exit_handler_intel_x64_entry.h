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

#ifndef EXIT_HANDLER_INTEL_X64_ENTRY_H
#define EXIT_HANDLER_INTEL_X64_ENTRY_H

#include <exit_handler/exit_handler_intel_x64.h>

/// Exit Handler
///
/// This is the "C" portion of the exit handler. Once the entry point has
/// finished its job, it hands control to this function, which trampolines
/// to a C++ exit handler dispatch which will ultimately handle the VM exit
///
/// @expects none
/// @ensures none
///
extern "C" void exit_handler(exit_handler_intel_x64 *exit_handler) noexcept;

#endif
