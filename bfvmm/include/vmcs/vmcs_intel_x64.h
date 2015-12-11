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

#ifndef VMCS_INTEL_X64_H
#define VMCS_INTEL_X64_H

#include <vmcs/vmcs.h>
#include <intrinsics/intrinsics_intel_x64.h>

class vmcs_intel_x64 : public vmcs
{
public:

    /// Default Constructor
    ///
    vmcs_intel_x64();

    /// Destructor
    ///
    ~vmcs_intel_x64() {}

    /// Init VMCS
    ///
    /// Initializes the VMCS. One of the goals of this function is to decouple
    /// the intrinsics and memory manager from the VMCS so that the VMCS can
    /// be tested.
    ///
    /// @param intrinsics the intrinsics class that this VMCS will use
    /// @param memory_manager the memory manager class that this VMCS will use
    /// @return success on success, failure otherwise
    ///
    vmcs_error::type init(intrinsics *intrinsics,
                          memory_manager *memory_manager) override;

    /// Launch VMM
    ///
    vmcs_error::type launch() override;

private:

    vmcs_error::type create_vmcs_region();

    uint64_t vmcs_region_size();

private:

    memory_manager *m_memory_manager;
    intrinsics_intel_x64 *m_intrinsics;

    page m_vmcs_region;
};

#endif
