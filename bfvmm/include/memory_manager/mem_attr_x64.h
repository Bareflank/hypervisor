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

#ifndef MEM_ATTR_X64_H
#define MEM_ATTR_X64_H

#include <intrinsics/x64.h>

// *INDENT-OFF*

namespace x64
{

namespace memory_attr
{
    using attr_type = uint64_t;

    constexpr const auto invalid          = 0x00000000UL;

    constexpr const auto rw               = 0x00000100UL;
    constexpr const auto re               = 0x00000200UL;
    constexpr const auto pt               = 0x00000300UL;

    constexpr const auto rw_uc            = 0x00000100UL;
    constexpr const auto rw_wc            = 0x00000101UL;
    constexpr const auto rw_wt            = 0x00000104UL;
    constexpr const auto rw_wp            = 0x00000105UL;
    constexpr const auto rw_wb            = 0x00000106UL;
    constexpr const auto rw_uc_m          = 0x00000107UL;

    constexpr const auto re_uc            = 0x00000200UL;
    constexpr const auto re_wc            = 0x00000201UL;
    constexpr const auto re_wt            = 0x00000204UL;
    constexpr const auto re_wp            = 0x00000205UL;
    constexpr const auto re_wb            = 0x00000206UL;
    constexpr const auto re_uc_m          = 0x00000207UL;

    constexpr const auto pt_uc            = 0x00000300UL;
    constexpr const auto pt_wc            = 0x00000301UL;
    constexpr const auto pt_wt            = 0x00000304UL;
    constexpr const auto pt_wp            = 0x00000305UL;
    constexpr const auto pt_wb            = 0x00000306UL;
    constexpr const auto pt_uc_m          = 0x00000307UL;

    template<class P, class T,
             class = typename std::enable_if<std::is_integral<P>::value>::type,
             class = typename std::enable_if<std::is_integral<T>::value>::type>
    auto mem_type_to_attr(P perm, T type)
    {
        // Memory types are defined in x64::memory_type, and do not contain
        // permission information which is needed by certain functions. This
        // function converts memory types to memory attributes given desired
        // permission information from the user.

        switch(perm)
        {
            case rw: break;
            case re: break;

            default:
                throw std::runtime_error("mem_type_to_attr failed: invalid permissions");
        }

        switch(type)
        {
            case memory_type::uncacheable: break;
            case memory_type::write_combining: break;
            case memory_type::write_through: break;
            case memory_type::write_protected: break;
            case memory_type::write_back: break;
            case memory_type::uncacheable_minus: break;

            default:
                throw std::runtime_error("mem_type_to_attr failed: invalid memory type");
        }

        return perm | type;
    }
}

}

// *INDENT-ON*

#endif
