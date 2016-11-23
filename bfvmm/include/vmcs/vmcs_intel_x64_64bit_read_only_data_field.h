//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#ifndef VMCS_INTEL_X64_64BIT_READ_ONLY_DATA_FIELD_H
#define VMCS_INTEL_X64_64BIT_READ_ONLY_DATA_FIELD_H

#include <bitmanip.h>
#include <vmcs/vmcs_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>

/// Intel x86_64 VMCS 64-bit Read-Only Data Fields
///
/// The following provides the interface for the 64-bit read-only data VMCS
/// fields as defined in Appendix B.2.2, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace guest_physical_address
{
    constexpr const auto addr = 0x0000000000002400UL;
    constexpr const auto name = "guest_physical_address";

    inline auto exists() noexcept
    {
        return msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::is_allowed1() &&
               msrs::ia32_vmx_procbased_ctls2::enable_ept::is_allowed1();
    }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }
}

}
}

// *INDENT-ON*

#endif
