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

#ifndef ENTRY_H
#define ENTRY_H

#include <stdint.h>
#include <error_codes.h>

/// Start VMM
///
/// This function starts the VMM. The driver entry uses the ELF loader
/// to call this "C" function from the kernel. Prior to executing this
/// function, a new stack is provided, and all exceptions are caught prior to
/// completing. To start the VMM, this function calls the vcpu_manager's
/// start function, which begins the processing of starting the vmm.
///
/// @expects none
/// @ensures none
///
/// @param arg unused (likely will contain the cpu's core # in the future)
/// @return ENTRY_SUCCESS on success, ENTRY_ERROR_UNKNOWN otherwise.
///
extern "C" int64_t start_vmm(uint64_t arg) noexcept;

/// Stop VMM
///
/// This function stops the VMM. The driver entry uses the ELF loader
/// to call this "C" function from the kernel. Prior to executing this
/// function, a new stack is provided, and all exceptions are caught prior to
/// completing. To stop the VMM, this function calls the vcpu_manager's
/// stop function, which begins the processing of stopping the vmm.
///
/// @expects none
/// @ensures none
///
/// @param arg unused (likely will contain the cpu's core # in the future)
/// @return ENTRY_SUCCESS on success, ENTRY_ERROR_UNKNOWN otherwise.
///
extern "C" int64_t stop_vmm(uint64_t arg) noexcept;

#endif
