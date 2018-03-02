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

#ifndef STATE_SAVE_INTEL_X64_H
#define STATE_SAVE_INTEL_X64_H

#pragma pack(push, 1)

struct state_save_intel_x64
{
    uint64_t rax;                   // 0x000
    uint64_t rbx;                   // 0x008
    uint64_t rcx;                   // 0x010
    uint64_t rdx;                   // 0x018
    uint64_t rbp;                   // 0x020
    uint64_t rsi;                   // 0x028
    uint64_t rdi;                   // 0x030
    uint64_t r08;                   // 0x038
    uint64_t r09;                   // 0x040
    uint64_t r10;                   // 0x048
    uint64_t r11;                   // 0x050
    uint64_t r12;                   // 0x058
    uint64_t r13;                   // 0x060
    uint64_t r14;                   // 0x068
    uint64_t r15;                   // 0x070
    uint64_t rip;                   // 0x078
    uint64_t rsp;                   // 0x080

    uint64_t vcpuid;                // 0x088
    uint64_t vmxon_ptr;             // 0x090
    uint64_t vmcs_ptr;              // 0x098
    uint64_t exit_handler_ptr;      // 0x0A0

    uint64_t user1;                 // 0x0A8
    uint64_t user2;                 // 0x0B0
    uint64_t user3;                 // 0x0B8

    uint64_t ymm00[4];              // 0x0C0
    uint64_t ymm01[4];              // 0x0E0
    uint64_t ymm02[4];              // 0x100
    uint64_t ymm03[4];              // 0x120
    uint64_t ymm04[4];              // 0x140
    uint64_t ymm05[4];              // 0x160
    uint64_t ymm06[4];              // 0x180
    uint64_t ymm07[4];              // 0x1A0
    uint64_t ymm08[4];              // 0x1C0
    uint64_t ymm09[4];              // 0x1E0
    uint64_t ymm10[4];              // 0x200
    uint64_t ymm11[4];              // 0x220
    uint64_t ymm12[4];              // 0x240
    uint64_t ymm13[4];              // 0x260
    uint64_t ymm14[4];              // 0x280
    uint64_t ymm15[4];              // 0x2A0

    uint64_t remaining_space_in_page[0x1A8];
};

#pragma pack(pop)

#endif
