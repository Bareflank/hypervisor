//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef VMCS_INTEL_X64_RESUME_H
#define VMCS_INTEL_X64_RESUME_H

#include <hve/arch/intel_x64/state_save.h>

/// Resume VMCS
///
/// Performs a VMRESUME, executing the guest described by this VMCS. This
/// function can be executed by the exit handler when it is done emulating
/// and instruction, or it can be executed to schedule another guest
///
extern "C" void vmcs_resume(
    state_save_intel_x64 *state_save) noexcept;

#endif
