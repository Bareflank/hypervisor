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

#ifndef PDPTE_X64_H
#define PDPTE_X64_H

#include <debug.h>
#include <bitmanip.h>

// *INDENT-OFF*

namespace x64
{
namespace pdpte
{
    constexpr const auto name = "pdpte";

    namespace present
    {
        constexpr const auto mask = 0x0000000000000001UL;
        constexpr const auto from = 0;
        constexpr const auto name = "present";
    }

    namespace reserved
    {
        constexpr const auto from = 0;
        constexpr const auto name = "reserved";

        inline auto mask() noexcept
        {
            auto phys_len = cpuid::addr_size::phys::get();
            auto upper = 0xFFFFFFFFFFFFFFFFULL << phys_len;
            return (upper | 0x1E6ULL);
        }
    }

    namespace pwt
    {
        constexpr const auto mask = 0x0000000000000008UL;
        constexpr const auto from = 3;
        constexpr const auto name = "pwt";
    }

    namespace pcd
    {
        constexpr const auto mask = 0x0000000000000010UL;
        constexpr const auto from = 4;
        constexpr const auto name = "pcd";
    }

    namespace page_directory_addr
    {
        constexpr const auto from = 12;
        constexpr const auto name = "page_directory_addr";

        inline auto mask() noexcept
        {
            auto phys_len = cpuid::addr_size::phys::get();
            auto upper = 0xFFFFFFFFFFFFFFFFULL << from;
            return (~(0xFFFFFFFFFFFFFFFFULL << phys_len) & upper);
        }
    }
}
}

// *INDENT-ON*

#endif
