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

#ifndef PAT_X64_H
#define PAT_X64_H

#include <memory_manager/mem_attr_x64.h>

/// @cond
/// *INDENT-OFF*

namespace x64
{

// The PAT has been constructed in such a way that you can take the
// x86_64 memory types defined in the Memory Cache Control section
// of Volume 3, and use them as an index into the PAT, and get the
// correct memory type as a result.
//
// Sadly, this doesn't work for page directories, as they do not have a
// PAT bit to set, and thus can only index into the first half of
// the PAT. Thankfully, memory types 2 and 3 are reserved, and thus
// would have blank entires in the PAT using this scheme. Therefore,
// we have filled in the blank entires with WB and WT, allowing
// page directories to use WB as needed.
//
// Using this scheme, when we map guest memory, we take take the
// memory type that the guest has, and use it as an index into the
// pat without conversions.

namespace pat
{
    constexpr const auto pat_value                  = 0x0706050406040100UL;

    constexpr const auto uncacheable_index          = 0x00000000UL;
    constexpr const auto write_combining_index      = 0x00000001UL;
    constexpr const auto write_through_index        = 0x00000002UL;
    constexpr const auto write_protected_index      = 0x00000005UL;
    constexpr const auto write_back_index           = 0x00000003UL;
    constexpr const auto uncacheable_minus_index    = 0x00000007UL;

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    auto mem_attr_to_pat_index(T attr)
    {
        // The attr parameter could either be an x64::memory_type,
        // or it could be a x64::memory_attr with the big difference
        // being memory attributes have permissions encoded in them.
        // This function can filter both and return the PAT index

        switch (attr & 0xF)
        {
            case memory_type::uncacheable: return uncacheable_index;
            case memory_type::write_combining: return write_combining_index;
            case memory_type::write_through: return write_through_index;
            case memory_type::write_protected: return write_protected_index;
            case memory_type::write_back: return write_back_index;
            case memory_type::uncacheable_minus: return uncacheable_minus_index;

            default:
                throw std::runtime_error("mem_attr_to_pat_index failed: invalid attr");
        };
    }
}

}

/// *INDENT-ON*
/// @endcond

#endif
