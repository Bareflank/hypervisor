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
#include <vmcs/vmcs_intel_x64.h>

// =============================================================================
//  Helper Structs
// =============================================================================

struct vmcs_region
{
    uint32_t revision_id;
};

// =============================================================================
//  Implementation
// =============================================================================

vmcs_intel_x64::vmcs_intel_x64() :
    m_intrinsics(0),
    m_memory_manager(0)
{
}

vmcs_error::type
vmcs_intel_x64::init(intrinsics *intrinsics,
                     memory_manager *memory_manager)
{
    if (intrinsics == 0 || memory_manager == 0)
        return vmcs_error::failure;

    // Ideally we would use dynamic_cast to get access to the intrinics
    // for this archiecture, simply to validate that we were passed the
    // correct class. Since the VMM does not have RTTI, we cannot use this
    // function.

    m_intrinsics = reinterpret_cast<intrinsics_intel_x64 *>(intrinsics);
    m_memory_manager = memory_manager;

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::launch()
{
    vmcs_error::type ret;

    if (m_intrinsics == 0 || m_memory_manager == 0)
        return vmcs_error::failure;

    std::cout << "launch: successfull" << std::endl;

    return vmcs_error::success;
}

vmcs_error::type
vmcs_intel_x64::create_vmcs_region()
{
    if (m_memory_manager->alloc_page(&m_vmcs_region) != memory_manager_error::success)
    {
        std::cout << "create_vmcs_region failed: "
                  << "out of memory" << std::endl;
        return vmcs_error::out_of_memory;
    }

    if (m_vmcs_region.size() < vmcs_region_size())
    {
        std::cout << "create_vmcs_region failed: "
                  << "the allocated page is not large enough:" << std::endl
                  << "    - page size: " << m_vmcs_region.size() << " "
                  << "    - vmxon/vmcs region size: " << vmcs_region_size()
                  << std::endl;
        return vmcs_error::not_supported;
    }

    if (((uintptr_t)m_vmcs_region.phys_addr() & 0x0000000000000FFF) != 0)
    {
        std::cout << "create_vmcs_region failed: "
                  << "the allocated page is not page aligned:" << std::endl
                  << "    - page phys: " << m_vmcs_region.phys_addr()
                  << std::endl;
        return vmcs_error::not_supported;
    }

    auto buf = (char *)m_vmcs_region.virt_addr();
    auto reg = (vmcs_region *)m_vmcs_region.virt_addr();

    // The information regading this MSR can be found in appendix A.1. For
    // the VMX capabilities check, we need the following:
    //
    // - Bits 30:0 contain the 31-bit VMCS revision identifier used by the
    //   processor. Processors that use the same VMCS revision identifier use
    //   the same size for VMCS regions (see subsequent item on bits 44:32)

    for (auto i = 0; i < m_vmcs_region.size(); i++)
        buf[i] = 0;

    reg->revision_id = m_intrinsics->read_msr(IA32_VMX_BASIC_MSR) & 0x7FFFFFFFF;

    return vmcs_error::success;
}

uint64_t
vmcs_intel_x64::vmcs_region_size()
{
    auto vmx_basic_msr = m_intrinsics->read_msr(IA32_VMX_BASIC_MSR);

    // The information regading this MSR can be found in appendix A.1. For
    // the VMX capabilities check, we need the following:
    //
    // - Bits 44:32 report the number of bytes that software should allocate
    //   for the VMXON region and any VMCS region. It is a value greater
    //   than 0 and at most 4096 (bit 44 is set if and only if bits 43:32 are
    //   clear).
    //
    //   Note: We basically ignore the above bits and just allocate 4K for each
    //   VMX region. The only thing we do with this function is ensure that
    //   the page that we were given is at least this big

    return (vmx_basic_msr >> 32) & 0x1FFF;
}
