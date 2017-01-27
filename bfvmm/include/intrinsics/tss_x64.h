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

#ifndef TSS_X64_H
#define TSS_X64_H

#include <stdint.h>

#pragma pack(push, 1)

struct tss_x64
{
    using integer_pointer = uintptr_t;

    uint32_t reserved1;
    uint32_t rsp0_lower;
    uint32_t rsp0_upper;
    uint32_t rsp1_lower;
    uint32_t rsp1_upper;
    uint32_t rsp2_lower;
    uint32_t rsp2_upper;
    uint32_t reserved2;
    uint32_t reserved3;
    uint32_t ist1_lower;
    uint32_t ist1_upper;
    uint32_t ist2_lower;
    uint32_t ist2_upper;
    uint32_t ist3_lower;
    uint32_t ist3_upper;
    uint32_t ist4_lower;
    uint32_t ist4_upper;
    uint32_t ist5_lower;
    uint32_t ist5_upper;
    uint32_t ist6_lower;
    uint32_t ist6_upper;
    uint32_t ist7_lower;
    uint32_t ist7_upper;
    uint32_t reserved4;
    uint32_t reserved5;
    uint16_t reserved6;
    uint16_t iomap;

    tss_x64() noexcept :
        reserved1(0),
        rsp0_lower(0),
        rsp0_upper(0),
        rsp1_lower(0),
        rsp1_upper(0),
        rsp2_lower(0),
        rsp2_upper(0),
        reserved2(0),
        reserved3(0),
        ist1_lower(0),
        ist1_upper(0),
        ist2_lower(0),
        ist2_upper(0),
        ist3_lower(0),
        ist3_upper(0),
        ist4_lower(0),
        ist4_upper(0),
        ist5_lower(0),
        ist5_upper(0),
        ist6_lower(0),
        ist6_upper(0),
        ist7_lower(0),
        ist7_upper(0),
        reserved4(0),
        reserved5(0),
        reserved6(0),
        iomap(0)
    {}
};

#pragma pack(pop)

#endif
