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

#ifndef VMCS_INTEL_X64_NATURAL_WIDTH_CONTROL_FIELDS_H
#define VMCS_INTEL_X64_NATURAL_WIDTH_CONTROL_FIELDS_H

#include <arch/intel_x64/vmcs/helpers.h>

/// Intel x86_64 VMCS Natural-Width Control Fields
///
/// The following provides the interface for the natural-width control VMCS
/// fields as defined in Appendix B.4.1, Vol. 3 of the Intel Software Developer's
/// Manual.
///

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace cr0_guest_host_mask
{
    constexpr const auto addr = 0x0000000000006000ULL;
    constexpr const auto name = "cr0_guest_host_mask";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace cr4_guest_host_mask
{
    constexpr const auto addr = 0x0000000000006002ULL;
    constexpr const auto name = "cr4_guest_host_mask";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace cr0_read_shadow
{
    constexpr const auto addr = 0x0000000000006004ULL;
    constexpr const auto name = "cr0_read_shadow";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace cr4_read_shadow
{
    constexpr const auto addr = 0x0000000000006006ULL;
    constexpr const auto name = "cr4_read_shadow";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace cr3_target_value_0
{
    constexpr const auto addr = 0x0000000000006008ULL;
    constexpr const auto name = "cr3_target_value_0";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace cr3_target_value_1
{
    constexpr const auto addr = 0x000000000000600AULL;
    constexpr const auto name = "cr3_target_value_1";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace cr3_target_value_2
{
    constexpr const auto addr = 0x000000000000600CULL;
    constexpr const auto name = "cr3_target_value_2";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

namespace cr3_target_value_3
{
    constexpr const auto addr = 0x000000000000600EULL;
    constexpr const auto name = "cr3_target_value_3";

    inline auto exists()
    { return true; }

    inline auto get()
    { return get_vmcs_field(addr, name, exists()); }

    inline auto get_if_exists(bool verbose = false)
    { return get_vmcs_field_if_exists(addr, name, verbose, exists()); }

    inline void set(value_type val)
    { set_vmcs_field(val, addr, name, exists()); }

    inline void set_if_exists(value_type val, bool verbose = false)
    { set_vmcs_field_if_exists(val, addr, name, verbose, exists()); }

    inline void dump(int level, std::string *msg = nullptr)
    { dump_vmcs_nhex(level, msg); }
}

}
}

// *INDENT-ON*

#endif
