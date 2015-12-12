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

#ifndef VMM_INTEL_X64_H
#define VMM_INTEL_X64_H

#include <vmm/vmm.h>
#include <intrinsics/intrinsics_intel_x64.h>

class vmm_intel_x64 : public vmm
{
public:

    /// Default Constructor
    ///
    vmm_intel_x64();

    /// Destructor
    ///
    virtual ~vmm_intel_x64() {}

    /// Init VMM
    ///
    /// Initializes the VMM. One of the goals of this function is to decouple
    /// the intrinsics and memory manager from the VMM so that the VMM can
    /// be tested.
    ///
    /// @param intrinsics the intrinsics class that this VMM will use
    /// @param memory_manager the memory manager class that this VMM will use
    /// @return success on success, failure otherwise
    ///
    virtual vmm_error::type init(intrinsics *intrinsics,
                                 memory_manager *memory_manager) override;

    /// Start VMM
    ///
    /// Starts the VMM. In the process of starting the VMM, several
    /// compatibility tests will be run to ensure that the VMM can in fact
    /// be used.
    ///
    /// @return not_supported if the compability tests fail, success on success
    ///         and failure otherwise
    ///
    virtual vmm_error::type start() override;

    /// Stop VMM
    ///
    /// Stops the VMM.
    ///
    /// @return success on success, failure otherwise
    ///
    virtual vmm_error::type stop() override;

protected:

    virtual vmm_error::type verify_cpuid_vmx_supported();
    virtual vmm_error::type verify_vmx_capabilities_msr();
    virtual vmm_error::type verify_ia32_vmx_cr0_fixed_msr();
    virtual vmm_error::type verify_ia32_vmx_cr4_fixed_msr();
    virtual vmm_error::type verify_ia32_feature_control_msr();
    virtual vmm_error::type verify_v8086_disabled();
    virtual vmm_error::type verify_vmx_operation_enabled();
    virtual vmm_error::type verify_vmx_operation_disabled();

    virtual vmm_error::type create_vmxon_region();
    virtual vmm_error::type release_vmxon_region();
    virtual vmm_error::type enable_vmx_operation();
    virtual vmm_error::type disable_vmx_operation();
    virtual vmm_error::type execute_vmxon();
    virtual vmm_error::type execute_vmxoff();

    virtual uint64_t vmxon_region_size();

private:

    friend class vmm_ut;

    bool m_vmxon_enabled;

    memory_manager *m_memory_manager;
    intrinsics_intel_x64 *m_intrinsics;

    page m_vmxon_page;
};

#endif
