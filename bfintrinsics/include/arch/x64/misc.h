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

#include <arch/x64/cpuid.h>

// *INDENT-OFF*

namespace x64
{

constexpr const auto page_size = 0x1000ULL;
constexpr const auto page_shift = 12ULL;
constexpr const auto cache_line_size = 64ULL;
constexpr const auto cache_line_shift = 6ULL;

namespace memory_type
{
    constexpr const auto uncacheable = 0x00000000ULL;
    constexpr const auto write_combining = 0x00000001ULL;
    constexpr const auto write_through = 0x00000004ULL;
    constexpr const auto write_protected = 0x00000005ULL;
    constexpr const auto write_back = 0x00000006ULL;
    constexpr const auto uncacheable_minus = 0x00000007ULL;
}

namespace memory_attr
{
    using attr_type = uint64_t;

    constexpr const auto invalid = 0x00000000UL;

    constexpr const auto rw = 0x00000100UL;
    constexpr const auto re = 0x00000200UL;
    constexpr const auto pt = 0x00000300UL;

    constexpr const auto rw_uc = 0x00000100UL;
    constexpr const auto rw_wc = 0x00000101UL;
    constexpr const auto rw_wt = 0x00000104UL;
    constexpr const auto rw_wp = 0x00000105UL;
    constexpr const auto rw_wb = 0x00000106UL;
    constexpr const auto rw_uc_m = 0x00000107UL;

    constexpr const auto re_uc = 0x00000200UL;
    constexpr const auto re_wc = 0x00000201UL;
    constexpr const auto re_wt = 0x00000204UL;
    constexpr const auto re_wp = 0x00000205UL;
    constexpr const auto re_wb = 0x00000206UL;
    constexpr const auto re_uc_m = 0x00000207UL;

    constexpr const auto pt_uc = 0x00000300UL;
    constexpr const auto pt_wc = 0x00000301UL;
    constexpr const auto pt_wt = 0x00000304UL;
    constexpr const auto pt_wp = 0x00000305UL;
    constexpr const auto pt_wb = 0x00000306UL;
    constexpr const auto pt_uc_m = 0x00000307UL;

    template<
        typename P,
        typename T,
        typename = std::enable_if<std::is_integral<P>::value>,
        typename = std::enable_if<std::is_integral<T>::value>
        >
    auto mem_type_to_attr(P perm, T type)
    {
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

namespace access_rights
{
    namespace type
    {
        constexpr const auto tss_busy = 0x0000000BU;
        constexpr const auto tss_available = 0x00000009U;

        constexpr const auto read_only = 0x00000000U;
        constexpr const auto read_only_accessed = 0x00000001U;
        constexpr const auto read_write = 0x00000002U;
        constexpr const auto read_write_accessed = 0x00000003U;
        constexpr const auto read_only_expand_down = 0x00000004U;
        constexpr const auto read_only_expand_down_accessed = 0x00000005U;
        constexpr const auto read_write_expand_down = 0x00000006U;
        constexpr const auto read_write_expand_down_accessed = 0x00000007U;

        constexpr const auto execute_only = 0x00000008U;
        constexpr const auto execute_only_accessed = 0x00000009U;
        constexpr const auto read_execute = 0x0000000AU;
        constexpr const auto read_execute_accessed = 0x0000000BU;
        constexpr const auto execute_only_conforming = 0x0000000CU;
        constexpr const auto execute_only_conforming_accessed = 0x0000000DU;
        constexpr const auto read_execute_conforming = 0x0000000EU;
        constexpr const auto read_execute_conforming_accessed = 0x0000000FU;
    }

    namespace dpl
    {
        constexpr const auto ring0 = 0x00000000U;
        constexpr const auto ring1 = 0x00000001U;
        constexpr const auto ring2 = 0x00000002U;
        constexpr const auto ring3 = 0x00000003U;
    }

    constexpr const auto ring0_cs_descriptor = 0x0000A09BU;
    constexpr const auto ring0_ss_descriptor = 0x0000C093U;
    constexpr const auto ring0_fs_descriptor = 0x00008093U;
    constexpr const auto ring0_gs_descriptor = 0x00008093U;
    constexpr const auto ring0_tr_descriptor = 0x0000008BU;

    constexpr const auto unusable = 0x00010000U;
}

namespace pat
{
    constexpr const auto pat_value = 0x0706050406040100UL;

    constexpr const auto uncacheable_index = 0x00000000UL;
    constexpr const auto write_combining_index = 0x00000001UL;
    constexpr const auto write_through_index = 0x00000002UL;
    constexpr const auto write_protected_index = 0x00000005UL;
    constexpr const auto write_back_index = 0x00000003UL;
    constexpr const auto uncacheable_minus_index = 0x00000007UL;

    template<class T, class = typename std::enable_if<std::is_integral<T>::value>::type>
    auto mem_attr_to_pat_index(T attr)
    {
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

namespace interrupt
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

// TODO:
//
// The PDPTE should be expanded to support all page types, all fields, and
// we should provide all of the get / set functions. The memory manager code
// would then use this instead of hard coding everything, and other code
// could use the same logic removing duplication.
//
// We should also provide a "general" page table type that only has fields that
// are shared
//

namespace page_table
{
    constexpr const auto num_entries = 512UL;
    constexpr const auto num_bytes = num_entries * sizeof(uintptr_t);

    template<class T, class F> auto index(const T virt, const F from)
    { return gsl::narrow_cast<std::ptrdiff_t>((virt & ((0x1FFULL) << from)) >> from); }

    namespace pml4
    {
        constexpr const auto from = 39U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x8000000000UL;
    }

    namespace pdpt
    {
        constexpr const auto from = 30U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x40000000UL;
    }

    namespace pd
    {
        constexpr const auto from = 21U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x200000UL;
    }

    namespace pt
    {
        constexpr const auto from = 12U;
        constexpr const auto size = 9U;
        constexpr const auto size_bytes = 0x1000UL;
    }
}

namespace pdpte
{
    namespace present
    {
        constexpr const auto mask = 0x0000000000000001ULL;
        constexpr const auto from = 0ULL;
        constexpr const auto name = "present";
    }

    namespace reserved
    {
        constexpr const auto from = 0ULL;
        constexpr const auto name = "reserved";

        inline auto mask() noexcept
        { return ((0xFFFFFFFFFFFFFFFFULL << cpuid::addr_size::phys::get()) | 0x1E6ULL); }
    }

    namespace pwt
    {
        constexpr const auto mask = 0x0000000000000008ULL;
        constexpr const auto from = 3ULL;
        constexpr const auto name = "pwt";
    }

    namespace pcd
    {
        constexpr const auto mask = 0x0000000000000010ULL;
        constexpr const auto from = 4ULL;
        constexpr const auto name = "pcd";
    }

    namespace page_directory_addr
    {
        constexpr const auto from = 12ULL;
        constexpr const auto name = "page_directory_addr";

        inline auto mask() noexcept
        {
            auto phys_len = cpuid::addr_size::phys::get();
            return (~(0xFFFFFFFFFFFFFFFFULL << phys_len) & (0xFFFFFFFFFFFFFFFFULL << from));
        }
    }
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
    auto bits = cpuid::addr_size::phys::get();
    auto mask = (0xFFFFFFFFFFFFFFFFULL >> bits) << bits;

    return ((addr & mask) == 0);
}

///
/// @param pas the physical address size
///
inline auto is_physical_address_valid(uintptr_t addr, uint64_t pas)
{
    auto mask = (0xFFFFFFFFFFFFFFFFULL >> pas) << pas;
    return ((addr & mask) == 0);
}

inline auto is_physical_address_valid(void *addr)
{ return is_physical_address_valid(reinterpret_cast<uintptr_t>(addr)); }
}

// *INDENT-ON*

#endif
