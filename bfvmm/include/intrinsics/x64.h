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

#ifndef X64_H
#define X64_H

// *INDENT-OFF*

namespace x64
{
namespace memory_type
{
    constexpr const auto uncacheable                             = 0x00000000U;
    constexpr const auto write_back                              = 0x00000006U;
}

namespace access_rights
{
    namespace type
    {
        constexpr const auto tss_busy                            = 0x0000000BU;
        constexpr const auto tss_available                       = 0x00000009U;

        constexpr const auto read_only                           = 0x00000000U;
        constexpr const auto read_only_accessed                  = 0x00000001U;
        constexpr const auto read_write                          = 0x00000002U;
        constexpr const auto read_write_accessed                 = 0x00000003U;
        constexpr const auto read_only_expand_down               = 0x00000004U;
        constexpr const auto read_only_expand_down_accessed      = 0x00000005U;
        constexpr const auto read_write_expand_down              = 0x00000006U;
        constexpr const auto read_write_expand_down_accessed     = 0x00000007U;

        constexpr const auto execute_only                        = 0x00000008U;
        constexpr const auto execute_only_accessed               = 0x00000009U;
        constexpr const auto read_execute                        = 0x0000000AU;
        constexpr const auto read_execute_accessed               = 0x0000000BU;
        constexpr const auto execute_only_conforming             = 0x0000000CU;
        constexpr const auto execute_only_conforming_accessed    = 0x0000000DU;
        constexpr const auto read_execute_conforming             = 0x0000000EU;
        constexpr const auto read_execute_conforming_accessed    = 0x0000000FU;
    }

    namespace dpl
    {
        constexpr const auto ring0                               = 0x00000000U;
        constexpr const auto ring1                               = 0x00000001U;
        constexpr const auto ring2                               = 0x00000002U;
        constexpr const auto ring3                               = 0x00000003U;
    }

    constexpr const auto ring0_cs_descriptor                     = 0x0000A09BU;
    constexpr const auto ring0_ss_descriptor                     = 0x0000C093U;
    constexpr const auto ring0_fs_descriptor                     = 0x00008093U;
    constexpr const auto ring0_gs_descriptor                     = 0x00008093U;
    constexpr const auto ring0_tr_descriptor                     = 0x0000008BU;

    constexpr const auto unusable                                = 0x00010000U;
}
}

// *INDENT-ON*

#endif
