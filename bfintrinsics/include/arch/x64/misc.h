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

#ifndef MISC_X64_H
#define MISC_X64_H

#include <bfdebug.h>
#include <bfbitmanip.h>

#include <arch/x64/cpuid.h>

// *INDENT-OFF*

namespace x64
{

constexpr const auto cache_line_size = 64ULL;
constexpr const auto cache_line_shift = 6ULL;

namespace exception
{
    constexpr const auto divide_error = 0U;
    constexpr const auto debug_exception = 1U;
    constexpr const auto nmi_interrupt = 2U;
    constexpr const auto breakpoint = 3U;
    constexpr const auto overflow = 4U;
    constexpr const auto bound_range_exceeded = 5U;
    constexpr const auto invalid_opcode = 6U;
    constexpr const auto device_not_available = 7U;
    constexpr const auto double_fault = 8U;
    constexpr const auto coprocessor_segment_overrun = 9U;
    constexpr const auto invalid_tss= 10U;
    constexpr const auto segment_not_present= 11U;
    constexpr const auto stack_segment_fault= 12U;
    constexpr const auto general_protection= 13U;
    constexpr const auto page_fault= 14U;
    constexpr const auto floating_point_error= 16U;
    constexpr const auto alignment_check= 17U;
    constexpr const auto machine_check= 18U;
    constexpr const auto simd_floating_point_exception= 19U;
    constexpr const auto virtualization_exception= 20U;
}

namespace memory_type
{
    using value_type = uint64_t;

    constexpr const auto uncacheable = 0x00000000ULL;
    constexpr const auto write_combining = 0x00000001ULL;
    constexpr const auto write_through = 0x00000004ULL;
    constexpr const auto write_protected = 0x00000005ULL;
    constexpr const auto write_back = 0x00000006ULL;
    constexpr const auto uncacheable_minus = 0x00000007ULL;
}

inline auto is_address_canonical(uintptr_t addr)
{ return ((addr <= 0x00007FFFFFFFFFFFULL) || (addr >= 0xFFFF800000000000ULL)); }

inline auto is_address_canonical(void *addr)
{ return is_address_canonical(reinterpret_cast<uintptr_t>(addr)); }

inline auto is_linear_address_valid(uintptr_t addr)
{ return is_address_canonical(addr); }

inline auto is_linear_address_valid(void *addr)
{ return is_address_canonical(addr); }

inline auto is_physical_address_valid(uintptr_t addr)
{
    auto size = cpuid::addr_size::phys::get();
    auto mask = (0xFFFFFFFFFFFFFFFFULL >> size) << size;

    return ((addr & mask) == 0);
}

inline auto is_physical_address_valid(uintptr_t addr, uint64_t size)
{
    auto mask = (0xFFFFFFFFFFFFFFFFULL >> size) << size;
    return ((addr & mask) == 0);
}

inline auto is_physical_address_valid(void *addr)
{ return is_physical_address_valid(reinterpret_cast<uintptr_t>(addr)); }

}

// *INDENT-ON*

#endif
