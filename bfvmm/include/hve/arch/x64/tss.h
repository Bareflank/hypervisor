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

#ifndef TSS_X64_H
#define TSS_X64_H

#include <cstdint>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace bfvmm::x64
{

#pragma pack(push, 1)

/* @cond */

struct tss {
    uint32_t reserved1{0};
    uint64_t rsp0{0};
    uint64_t rsp1{0};
    uint64_t rsp2{0};
    uint32_t reserved2{0};
    uint32_t reserved3{0};
    uint64_t ist1{0};
    uint64_t ist2{0};
    uint64_t ist3{0};
    uint64_t ist4{0};
    uint64_t ist5{0};
    uint64_t ist6{0};
    uint64_t ist7{0};
    uint32_t reserved4{0};
    uint32_t reserved5{0};
    uint16_t reserved6{0};
    uint16_t iomap{0};

    uint8_t pad[3992];
};

static_assert(sizeof(tss) == 0x1000, "TSS is not a page in size");

/* @endcond */

#pragma pack(pop)

}

#endif
