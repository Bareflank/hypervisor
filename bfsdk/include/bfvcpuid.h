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

#ifndef BFVCPUID_H
#define BFVCPUID_H

#include <cstdint>

// *INDENT-OFF*

namespace vcpuid
{
    using type = uint64_t;

    constexpr const auto reserved = 0x8000000000000000UL;

    constexpr const auto invalid = 0xFFFFFFFFFFFFFFFFUL;
    constexpr const auto current = 0xFFFFFFFFFFFFFFF0UL;

    constexpr const auto guest_mask = 0xFFFFFFFFFFFF0000UL;
    constexpr const auto guest_from = 16;
}

// *INDENT-ON*

#endif
