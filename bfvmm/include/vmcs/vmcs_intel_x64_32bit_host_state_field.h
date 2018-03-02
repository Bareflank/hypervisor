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

#ifndef VMCS_INTEL_X64_32BIT_HOST_STATE_FIELD_H
#define VMCS_INTEL_X64_32BIT_HOST_STATE_FIELD_H

#include <vmcs/vmcs_intel_x64.h>

/// Intel x86_64 VMCS 32-bit Host-State Data Fields
///
/// The following provides the interface for the 32-bit host-state VMCS
/// fields as defined in Appendix B.3.4, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace host_ia32_sysenter_cs
{
    constexpr const auto addr = 0x0000000000004C00UL;
    constexpr const auto name = "host_ia32_sysenter_cs";

    inline bool exists() noexcept
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false) noexcept
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set(T val) { set_vmcs_field(val, addr, name, exists()); }

    template <class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    void set_if_exists(T val, bool verbose = false) noexcept
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }
}

}
}

// *INDENT-ON*

#endif
