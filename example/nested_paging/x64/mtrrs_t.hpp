/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef MTRRS_T_HPP
#define MTRRS_T_HPP

#include "intrinsic_cpuid.hpp"
#include "memory_type.hpp"
#include "range_t.hpp"

#include <mk_interface.hpp>

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/sort.hpp>
#include <bsl/touch.hpp>

namespace example
{
    /// @brief defines the CPUID feature identifier bit for MTRR
    constexpr bsl::safe_umx MAX_RANGES{bsl::to_umx(512)};

    /// @brief defines the CPUID feature identifier index
    constexpr bsl::safe_umx CPUID_FEATURE_IDENTIFIERS{bsl::to_umx(0x00000001U)};
    /// @brief defines the CPUID feature identifier bit for MTRR
    constexpr bsl::safe_umx CPUID_FEATURE_IDENTIFIERS_MTRR{bsl::to_umx(0x00001000U)};

    /// @brief defines the CPUID linear/physical address size index
    constexpr bsl::safe_umx CPUID_LP_ADDRESS_SIZE{bsl::to_umx(0x80000008U)};
    /// @brief defines the CPUID linear/physical address size phys addr bits
    constexpr bsl::safe_umx CPUID_LP_ADDRESS_SIZE_PHYS_ADDR_BITS{bsl::to_umx(0x000000FFU)};

    /// @brief defines the MTRRcap MSR
    constexpr bsl::safe_u32 MTRRCAP{bsl::to_u32(0x000000FEU)};
    /// @brief defines the MTRRcap MSR VCNT field
    constexpr bsl::safe_umx MTRRCAP_VCNT{bsl::to_umx(0x00000000000000FFU)};
    /// @brief defines the MTRRcap MSR FIX field
    constexpr bsl::safe_umx MTRRCAP_FIX{bsl::to_umx(0x0000000000000100U)};

    /// @brief defines the MTRRdefType MSR
    constexpr bsl::safe_u32 MTRRDEFTYPE{bsl::to_u32(0x000002FFU)};
    /// @brief defines the MTRRdefType MSR type field
    constexpr bsl::safe_umx MTRRDEFTYPE_TYPE{bsl::to_umx(0x00000000000000FFU)};
    /// @brief defines the MTRRdefType MSR fixed range enable field
    constexpr bsl::safe_umx MTRRDEFTYPE_FE{bsl::to_umx(0x0000000000000400U)};
    /// @brief defines the MTRRdefType MSR enable field
    constexpr bsl::safe_umx MTRRDEFTYPE_E{bsl::to_umx(0x0000000000000800U)};

    /// @brief defines the MTRRfix64K_00000 MSR
    constexpr bsl::safe_u32 MTRRFIX64K_00000{bsl::to_u32(0x000000250U)};
    /// @brief defines the MTRRfix16K_80000 MSR
    constexpr bsl::safe_u32 MTRRFIX16K_80000{bsl::to_u32(0x000000258U)};
    /// @brief defines the MTRRfix16K_A0000 MSR
    constexpr bsl::safe_u32 MTRRFIX16K_A0000{bsl::to_u32(0x000000259U)};
    /// @brief defines the MTRRfix4K_C0000 MSR
    constexpr bsl::safe_u32 MTRRFIX4K_C0000{bsl::to_u32(0x000000268U)};
    /// @brief defines the MTRRfix4K_C8000 MSR
    constexpr bsl::safe_u32 MTRRFIX4K_C8000{bsl::to_u32(0x000000269U)};
    /// @brief defines the MTRRfix4K_D0000 MSR
    constexpr bsl::safe_u32 MTRRFIX4K_D0000{bsl::to_u32(0x00000026AU)};
    /// @brief defines the MTRRfix4K_D8000 MSR
    constexpr bsl::safe_u32 MTRRFIX4K_D8000{bsl::to_u32(0x00000026BU)};
    /// @brief defines the MTRRfix4K_E0000 MSR
    constexpr bsl::safe_u32 MTRRFIX4K_E0000{bsl::to_u32(0x00000026CU)};
    /// @brief defines the MTRRfix4K_E8000 MSR
    constexpr bsl::safe_u32 MTRRFIX4K_E8000{bsl::to_u32(0x00000026DU)};
    /// @brief defines the MTRRfix4K_F0000 MSR
    constexpr bsl::safe_u32 MTRRFIX4K_F0000{bsl::to_u32(0x00000026EU)};
    /// @brief defines the MTRRfix4K_F8000 MSR
    constexpr bsl::safe_u32 MTRRFIX4K_F8000{bsl::to_u32(0x00000026FU)};

    /// @brief defines the memory type mask for fixed ranges
    constexpr bsl::safe_umx MTRR_FIX_MASK{bsl::to_umx(0x00000000000000FFU)};
    /// @brief defines the memory type shift for fixed ranges
    constexpr bsl::safe_umx MTRR_FIX_SHFT{bsl::to_umx(8)};
    /// @brief defines the total number of MTRRs per MSR for fixed ranges
    constexpr bsl::safe_umx MTRR_FIX_MTRRS_PER_MSR{bsl::to_umx(8)};

    /// @brief defines the address of MTRRFIX64K_00000
    constexpr bsl::safe_umx MTRRFIX64K_00000_ADDR{bsl::to_umx(0x0000000000000000U)};
    /// @brief defines the size of MTRRFIX64K_00000
    constexpr bsl::safe_umx MTRRFIX64K_00000_SIZE{bsl::to_umx(0x10000U)};
    /// @brief defines the address of MTRRFIX16K_80000
    constexpr bsl::safe_umx MTRRFIX16K_80000_ADDR{bsl::to_umx(0x0000000000080000U)};
    /// @brief defines the size of MTRRFIX16K_80000
    constexpr bsl::safe_umx MTRRFIX16K_80000_SIZE{bsl::to_umx(0x4000U)};
    /// @brief defines the address of MTRRFIX16K_A0000
    constexpr bsl::safe_umx MTRRFIX16K_A0000_ADDR{bsl::to_umx(0x00000000000A0000U)};
    /// @brief defines the size of MTRRFIX16K_A0000
    constexpr bsl::safe_umx MTRRFIX16K_A0000_SIZE{bsl::to_umx(0x4000U)};
    /// @brief defines the address of MTRRFIX4K_C0000
    constexpr bsl::safe_umx MTRRFIX4K_C0000_ADDR{bsl::to_umx(0x00000000000C0000U)};
    /// @brief defines the size of MTRRFIX4K_C0000
    constexpr bsl::safe_umx MTRRFIX4K_C0000_SIZE{bsl::to_umx(0x1000U)};
    /// @brief defines the address of MTRRFIX4K_C8000
    constexpr bsl::safe_umx MTRRFIX4K_C8000_ADDR{bsl::to_umx(0x00000000000C8000U)};
    /// @brief defines the size of MTRRFIX4K_C8000
    constexpr bsl::safe_umx MTRRFIX4K_C8000_SIZE{bsl::to_umx(0x1000U)};
    /// @brief defines the address of MTRRFIX4K_D0000
    constexpr bsl::safe_umx MTRRFIX4K_D0000_ADDR{bsl::to_umx(0x00000000000D0000U)};
    /// @brief defines the size of MTRRFIX4K_D0000
    constexpr bsl::safe_umx MTRRFIX4K_D0000_SIZE{bsl::to_umx(0x1000U)};
    /// @brief defines the address of MTRRFIX4K_D8000
    constexpr bsl::safe_umx MTRRFIX4K_D8000_ADDR{bsl::to_umx(0x00000000000D8000U)};
    /// @brief defines the size of MTRRFIX4K_D8000
    constexpr bsl::safe_umx MTRRFIX4K_D8000_SIZE{bsl::to_umx(0x1000U)};
    /// @brief defines the address of MTRRFIX4K_E0000
    constexpr bsl::safe_umx MTRRFIX4K_E0000_ADDR{bsl::to_umx(0x00000000000E0000U)};
    /// @brief defines the size of MTRRFIX4K_E0000
    constexpr bsl::safe_umx MTRRFIX4K_E0000_SIZE{bsl::to_umx(0x1000U)};
    /// @brief defines the address of MTRRFIX4K_E8000
    constexpr bsl::safe_umx MTRRFIX4K_E8000_ADDR{bsl::to_umx(0x00000000000E8000U)};
    /// @brief defines the size of MTRRFIX4K_E8000
    constexpr bsl::safe_umx MTRRFIX4K_E8000_SIZE{bsl::to_umx(0x1000U)};
    /// @brief defines the address of MTRRFIX4K_F0000
    constexpr bsl::safe_umx MTRRFIX4K_F0000_ADDR{bsl::to_umx(0x00000000000F0000U)};
    /// @brief defines the size of MTRRFIX4K_F0000
    constexpr bsl::safe_umx MTRRFIX4K_F0000_SIZE{bsl::to_umx(0x1000U)};
    /// @brief defines the address of MTRRFIX4K_F8000
    constexpr bsl::safe_umx MTRRFIX4K_F8000_ADDR{bsl::to_umx(0x00000000000F8000U)};
    /// @brief defines the size of MTRRFIX4K_F8000
    constexpr bsl::safe_umx MTRRFIX4K_F8000_SIZE{bsl::to_umx(0x1000U)};

    /// @brief defines the MTRRphysBase MSR
    constexpr bsl::safe_u32 MTRRPHYSBASE{bsl::to_u32(0x000000200U)};
    /// @brief defines the MTRRphysMask MSR
    constexpr bsl::safe_u32 MTRRPHYSMASK{bsl::to_u32(0x000000201U)};

    /// <!-- description -->
    ///   @brief Implements the sort function that we use for a range_t
    ///
    /// <!-- inputs/outputs -->
    ///   @param a the first element to compare
    ///   @param b the second element to compare
    ///   @return Returns true if a is less b, false otherwise
    ///
    [[nodiscard]] constexpr auto
    range_t_sort_cmp(range_t const &a, range_t const &b) noexcept -> bool
    {
        if (!a.addr) {
            return false;
        }

        if (!b.addr) {
            return true;
        }

        return a.addr < b.addr;
    };

    /// @class example::mtrrs_t
    ///
    /// <!-- description -->
    ///   @brief Parses the MTRRs and provides a continuous, non-overlapping
    ///     view of the ranges as needed.
    ///
    class mtrrs_t final
    {
        /// @brief stores the ranges associated with this mtrrs_t
        bsl::array<range_t, MAX_RANGES.get()> m_ranges{};
        /// @brief stores the number of ranges in the list.
        bsl::safe_umx m_ranges_count{};

        /// <!-- description -->
        ///   @brief Returns true if the provided address is 4k page aligned
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns true if the provided address is 4k page aligned
        ///
        [[nodiscard]] static constexpr auto
        is_page_4k_aligned(bsl::safe_umx const &addr) noexcept -> bool
        {
            constexpr bsl::safe_u64 mask_4k{bsl::to_umx(0xFFFU)};
            return (addr & mask_4k) == bsl::ZERO_UMAX;
        }

        /// <!-- description -->
        ///   @brief Returns true if the provided address is 2m page aligned
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to query
        ///   @return Returns true if the provided address is 2m page aligned
        ///
        [[nodiscard]] static constexpr auto
        is_page_2m_aligned(bsl::safe_umx const &addr) noexcept -> bool
        {
            constexpr bsl::safe_u64 mask_2m{bsl::to_umx(0x1FFFFFU)};
            return (addr & mask_2m) == bsl::ZERO_UMAX;
        }
        /// <!-- description -->
        ///   @brief Returns the combination of two memory type based on the
        ///     memory combining rules defined in the AMD/Intel manuals.
        ///
        /// <!-- inputs/outputs -->
        ///   @param r1 the first range to combine
        ///   @param r2 the second range to combine
        ///   @return Returns the combination of two memory type based on the
        ///     memory combining rules defined in the AMD/Intel manuals.
        ///
        [[nodiscard]] static constexpr auto
        combine(range_t const &r1, range_t const &r2) noexcept -> bsl::safe_umx
        {
            if (r1.dflt) {
                return r2.type;
            }

            if (r2.dflt) {
                return r1.type;
            }

            /// NOTE:
            /// - "a. If the memory types are identical, then that memory type
            ///    is used."
            ///

            if (r1.type == r2.type) {
                return r1.type;
            }

            /// NOTE:
            /// - "b. If at least one of the memory types is UC, the UC memory
            ///    type is used."
            ///

            if (r1.type == MEMORY_TYPE_UC) {
                return MEMORY_TYPE_UC;
            }

            if (r2.type == MEMORY_TYPE_UC) {
                return MEMORY_TYPE_UC;
            }

            /// NOTE:
            /// - "c. If at least one of the memory types is WT, and the only
            ///    other memory type is WB, then the WT memory type is used"
            ///

            if (r1.type == MEMORY_TYPE_WT) {
                if (r2.type == MEMORY_TYPE_WB) {
                    return MEMORY_TYPE_WT;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            if (r2.type == MEMORY_TYPE_WT) {
                if (r1.type == MEMORY_TYPE_WB) {
                    return MEMORY_TYPE_WT;
                }

                bsl::touch();
            }
            else {
                bsl::touch();
            }

            /// NOTE:
            /// - "d. If the combination of memory types is not listed Steps A
            ///    through C immediately above, then the memory type used is
            ///    undefined"
            ///

            return MEMORY_TYPE_UC;
        }

        /// <!-- description -->
        ///   @brief Adds a range to the list. This version of the function
        ///     does not attempt to clean up the ranges in the list. It
        ///     simply adds the range to the list and moves on.
        ///
        /// <!-- inputs/outputs -->
        ///   @param r the range to add
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_range(range_t const &r) noexcept -> bsl::errc_type
        {
            auto *const ptr{m_ranges.at_if(m_ranges_count)};
            if (bsl::unlikely(nullptr == ptr)) {
                bsl::error() << "mtrrs_t full\n" << bsl::here();
                return bsl::errc_failure;
            }

            *ptr = r;
            ++m_ranges_count;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds a range to the list. If the range that is being added
        ///     is a subset of any other range, or a range is a subset of the
        ///     range being added, the subsets are split. Any intersecting
        ///     ranges that are not subsets will cause this function to fail
        ///     as they are not supported by this algorithm.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address of the range
        ///   @param size the size of the range
        ///   @param type the type of memory in the range
        ///     type for all of memory, false otherwise
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_range(
            bsl::safe_umx const &addr,
            bsl::safe_umx const &size,
            bsl::safe_umx const &type) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            range_t r1{addr, size, type, false};

            if (bsl::unlikely(!this->is_page_4k_aligned(addr))) {
                bsl::error() << "addr is not 4k page aligned: "    // --
                             << bsl::hex(addr)                     // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_4k_aligned(size))) {
                bsl::error() << "size is not 4k page aligned: "    // --
                             << bsl::hex(size)                     // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < m_ranges_count; ++i) {
                auto *const r2{m_ranges.at_if(i)};

                auto const r1_l{r1.addr};
                auto const r1_r{r1.addr + r1.size};
                auto const r2_l{r2->addr};
                auto const r2_r{r2->addr + r2->size};

                /// NOTE:
                /// - If the range has a size of 0, there is no range to add
                ///   and we can stop. This could either happen because we
                ///   were given a 0 sized range to start, or the range we
                ///   were overlaps multiple ranges, in which case we have to
                ///   slowly remove from the provided range until it is 0, and
                ///   this will stop the loop when it is done.
                ///

                if (r1.size.is_zero()) {
                    break;
                }

                /// NOTE:
                /// - We need to scan the ranges until we find the first
                ///   range in the list that the provided range actually
                ///   intersects. For example:
                ///
                ///   ----------------------------------------
                ///   |    |              |  +++++           |
                ///   |    |              |  + 1 +    2      |
                ///   |    |              |  +++++           |
                ///   ----------------------------------------
                ///
                ///   Until the left side of r1 is greater than or equal to
                ///   the left side of r2, we can keep scanning because r1
                ///   and r2 do not intersect. Note that, you might be
                ///   thinking about, what if r1's right side overlaps into
                ///   r2. In this case, it would mean that r1's left side is
                ///   greater than or equal to the range to the left, which
                ///   means we have found a match. In other words, we only
                ///   have to pay attention to the left side, because if
                ///   the right side is an issue, the left side must also
                ///   be an issue with the adjacent range, which is really the
                ///   r2 we should be concerned with.
                ///
                /// - It should be noted that the above assumes that the
                ///   entire physical address range is represented by a range.
                ///   Meaning, there are not wholes. To ensure this, we the
                ///   first thing we do is fill the range list with the
                ///   default range that goes from 0 to MAX. From there, this
                ///   algorithm will perform it's work to add the range, and
                ///   then sort the list to ensure the list of ranges continues
                ///   to completely cover the entire physical address range.
                ///

                if (!(r1_l < r2_r)) {
                    continue;
                }

                /// NOTE:
                /// - Ok, if we got this far, it means that we have found a
                ///   range that intersects. Now, we need to handle the
                ///   different types of scenarios that might occur.
                ///

                if (r1_l == r2_l) {

                    /// Case #1:
                    /// - In this case, r1's left side is the same as r2's left
                    ///   side, meaning they are touching. When this happens,
                    ///   we need to divide r2 into two ranges.
                    ///
                    /// --------------------
                    /// |         2        |
                    /// |+++++             |
                    /// |+ 1 +             |
                    /// |+++++             |
                    /// |                  |
                    /// --------------------
                    ///
                    /// or
                    ///
                    /// --------------------
                    /// |         2        |
                    /// |++++++++++++++++++++++
                    /// |+ 1                  +
                    /// |++++++++++++++++++++++
                    /// |                  |
                    /// --------------------
                    ///

                    if (r1_r < r2_r) {
                        auto const new_r1_addr{r1.addr};
                        auto const new_r1_size{r1.size};
                        auto const new_r1_type{this->combine(r1, *r2)};
                        bool const new_r1_dflt{false};

                        ret = this->add_range({new_r1_addr, new_r1_size, new_r1_type, new_r1_dflt});
                        if (bsl::unlikely(!ret)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        auto const new_r2_addr{r1_r};
                        auto const new_r2_size{r2_r - r1_r};
                        auto const new_r2_type{r2->type};
                        bool const new_r2_dflt{r2->dflt};

                        ret = this->add_range({new_r2_addr, new_r2_size, new_r2_type, new_r2_dflt});
                        if (bsl::unlikely(!ret)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        r1.addr = bsl::ZERO_UMAX;
                        r1.size = bsl::ZERO_UMAX;
                    }
                    else {
                        auto const new_r1_addr{r1.addr};
                        auto const new_r1_size{r2->size};
                        auto const new_r1_type{this->combine(r1, *r2)};
                        bool const new_r1_dflt{false};

                        ret = this->add_range({new_r1_addr, new_r1_size, new_r1_type, new_r1_dflt});
                        if (bsl::unlikely(!ret)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        r1.addr = r2_r;
                        r1.size = r1_r - r2_r;
                    }

                    r2->addr = bsl::safe_umx::failure();
                    r2->size = bsl::safe_umx::failure();
                    r2->type = bsl::safe_umx::failure();
                    r2->dflt = false;
                    --m_ranges_count;

                    bsl::sort(m_ranges, &range_t_sort_cmp);
                }
                else {
                    /// Case #2:
                    /// - In this case, r1 is inside r1, meaning their left
                    ///   sides are not touching. This will force us to add
                    ///   2 or 3 ranges depending on the right side of r1.
                    ///
                    /// --------------------
                    /// |         2        |
                    /// |   +++++          |
                    /// |   + 1 +          |
                    /// |   +++++          |
                    /// |                  |
                    /// --------------------
                    ///
                    /// or
                    ///
                    /// --------------------
                    /// |         2        |
                    /// |   +++++++++++++++++++
                    /// |   + 1               +
                    /// |   +++++++++++++++++++
                    /// |                  |
                    /// --------------------
                    ///

                    if (r1_r < r2_r) {
                        auto const new_r1_addr{r2->addr};
                        auto const new_r1_size{r1_l - r2_l};
                        auto const new_r1_type{r2->type};
                        bool const new_r1_dflt{r2->dflt};

                        ret = this->add_range({new_r1_addr, new_r1_size, new_r1_type, new_r1_dflt});
                        if (bsl::unlikely(!ret)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        auto const new_r2_addr{r1.addr};
                        auto const new_r2_size{r1.size};
                        auto const new_r2_type{this->combine(r1, *r2)};
                        bool const new_r2_dflt{false};

                        ret = this->add_range({new_r2_addr, new_r2_size, new_r2_type, new_r2_dflt});
                        if (bsl::unlikely(!ret)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        auto const new_r3_addr{r1_r};
                        auto const new_r3_size{r2_r - r1_r};
                        auto const new_r3_type{r2->type};
                        bool const new_r3_dflt{r2->dflt};

                        ret = this->add_range({new_r3_addr, new_r3_size, new_r3_type, new_r3_dflt});
                        if (bsl::unlikely(!ret)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        r1.addr = bsl::ZERO_UMAX;
                        r1.size = bsl::ZERO_UMAX;
                    }
                    else {
                        auto const new_r1_addr{r2->addr};
                        auto const new_r1_size{r1_l - r2_l};
                        auto const new_r1_type{r2->type};
                        bool const new_r1_dflt{r2->dflt};

                        ret = this->add_range({new_r1_addr, new_r1_size, new_r1_type, new_r1_dflt});
                        if (bsl::unlikely(!ret)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        auto const new_r2_addr{r1.addr};
                        auto const new_r2_size{r2_r - r1_l};
                        auto const new_r2_type{this->combine(r1, *r2)};
                        bool const new_r2_dflt{false};

                        ret = this->add_range({new_r2_addr, new_r2_size, new_r2_type, new_r2_dflt});
                        if (bsl::unlikely(!ret)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return bsl::errc_failure;
                        }

                        r1.addr = r2_r;
                        r1.size = r1_r - r2_r;
                    }

                    r2->addr = bsl::safe_umx::failure();
                    r2->size = bsl::safe_umx::failure();
                    r2->type = bsl::safe_umx::failure();
                    r2->dflt = false;
                    --m_ranges_count;

                    bsl::sort(m_ranges, &range_t_sort_cmp);
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Once all of the ranges have been added, we can compress
        ///     the range list to reduce the overall size of the list.
        ///     Compression is simple. If two adjacent ranges have the same
        ///     type, we can combine them into a single range. Basically this
        ///     means we need to modify one range to be bigger and remove
        ///     the other range. Continue this process until we have scanned
        ///     the entire range list.
        ///
        /// <!-- inputs/outputs -->
        ///
        constexpr void
        compress_ranges() noexcept
        {
            bsl::safe_umx i{bsl::ONE_UMAX};

            if (m_ranges.size() == bsl::ONE_UMAX) {
                return;
            }

            while (i < m_ranges_count) {
                auto *const r1{m_ranges.at_if(i - bsl::ONE_UMAX)};
                auto *const r2{m_ranges.at_if(i)};

                if (r1->type == r2->type) {
                    r1->size += r2->size;

                    r2->addr = bsl::safe_umx::failure();
                    r2->size = bsl::safe_umx::failure();
                    r2->type = bsl::safe_umx::failure();
                    r2->dflt = false;
                    --m_ranges_count;

                    bsl::sort(m_ranges, &range_t_sort_cmp);
                }
                else {
                    ++i;
                }
            }
        }

        /// <!-- description -->
        ///   @brief Adds the 64k Fixed Range MTRRs starting at 0x00000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix64k_00000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX64K_00000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX64K_00000_SIZE};
                auto const addr{MTRRFIX64K_00000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the 16k Fixed Range MTRRs starting at 0x80000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix16k_80000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX16K_80000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX16K_80000_SIZE};
                auto const addr{MTRRFIX16K_80000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the 16k Fixed Range MTRRs starting at 0xA0000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix16k_a0000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX16K_A0000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX16K_A0000_SIZE};
                auto const addr{MTRRFIX16K_A0000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the 4k Fixed Range MTRRs starting at 0xC0000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix4k_c0000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX4K_C0000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX4K_C0000_SIZE};
                auto const addr{MTRRFIX4K_C0000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the 4k Fixed Range MTRRs starting at 0xC8000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix4k_c8000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX4K_C8000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX4K_C8000_SIZE};
                auto const addr{MTRRFIX4K_C8000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the 4k Fixed Range MTRRs starting at 0xD0000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix4k_d0000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX4K_D0000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX4K_D0000_SIZE};
                auto const addr{MTRRFIX4K_D0000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the 4k Fixed Range MTRRs starting at 0xD8000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix4k_d8000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX4K_D8000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX4K_D8000_SIZE};
                auto const addr{MTRRFIX4K_D8000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the 4k Fixed Range MTRRs starting at 0xE0000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix4k_e0000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX4K_E0000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX4K_E0000_SIZE};
                auto const addr{MTRRFIX4K_E0000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the 4k Fixed Range MTRRs starting at 0xE8000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix4k_e8000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX4K_E8000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX4K_E8000_SIZE};
                auto const addr{MTRRFIX4K_E8000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the 4k Fixed Range MTRRs starting at 0xF0000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix4k_f0000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX4K_F0000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX4K_F0000_SIZE};
                auto const addr{MTRRFIX4K_F0000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Adds the 4k Fixed Range MTRRs starting at 0xF8000.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_mtrr_fix4k_f8000(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx mtrr{};
            bsl::safe_umx shft{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRFIX4K_F8000, mtrr);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < MTRR_FIX_MTRRS_PER_MSR; ++i) {
                auto const size{MTRRFIX4K_F8000_SIZE};
                auto const addr{MTRRFIX4K_F8000_ADDR + (size * i)};
                auto const mask{MTRR_FIX_MASK << shft};
                auto const type{(mtrr & mask) >> shft};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                shft += MTRR_FIX_SHFT;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the base address portion of physbase
        ///
        /// <!-- inputs/outputs -->
        ///   @param physbase the physbase to convert
        ///   @return Returns the base address portion of physbase
        ///
        [[nodiscard]] static constexpr auto
        physbase_to_addr(bsl::safe_umx const &physbase) noexcept -> bsl::safe_umx
        {
            constexpr bsl::safe_umx mask{bsl::to_umx(0xFFFFFFFFFFFFF000U)};
            return physbase & mask;
        }

        /// <!-- description -->
        ///   @brief Returns the size portion of physmask using the conversion
        ///     logic defined in the manual.
        ///
        /// <!-- inputs/outputs -->
        ///   @param physmask the physmask to convert
        ///   @param pas the physical address size
        ///   @return Returns the size portion of physmask using the conversion
        ///     logic defined in the manual.
        ///
        [[nodiscard]] static constexpr auto
        physmask_to_size(                     // --
            bsl::safe_umx const &physmask,    // --
            bsl::safe_umx const &pas) noexcept -> bsl::safe_umx
        {
            constexpr bsl::safe_umx mask{bsl::to_umx(0xFFFFFFFFFFFFF000U)};
            return (~(physmask & mask) & ((bsl::ONE_UMAX << pas) - bsl::ONE_UMAX)) + bsl::ONE_UMAX;
        }

        /// <!-- description -->
        ///   @brief Returns the memory type portion of physbase
        ///
        /// <!-- inputs/outputs -->
        ///   @param physbase the physbase to convert
        ///   @return Returns the memory type portion of physbase
        ///
        [[nodiscard]] static constexpr auto
        physbase_to_type(bsl::safe_umx const &physbase) noexcept -> bsl::safe_umx
        {
            constexpr bsl::safe_umx mask{bsl::to_umx(0x00000000000000FFU)};
            return physbase & mask;
        }

        /// <!-- description -->
        ///   @brief Returns true if the valid bit is set in physmask,
        ///     false otherwise.
        ///
        /// <!-- inputs/outputs -->
        ///   @param physmask the physmask to query
        ///   @return Returns true if the valid bit is set in physmask,
        ///     false otherwise.
        ///
        [[nodiscard]] static constexpr auto
        physmask_to_valid(bsl::safe_umx const &physmask) noexcept -> bool
        {
            constexpr bsl::safe_umx mask{bsl::to_umx(0x0000000000000800U)};
            return (physmask & mask).is_pos();
        }

        /// <!-- description -->
        ///   @brief Parses all of the variable range MTRRs and adds them
        ///     to the list.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @param vcnt the total number of supported variable range MTRRs
        ///   @param pas the physical address size
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        add_variable_range(
            syscall::bf_handle_t &handle,
            bsl::safe_u32 const &vcnt,
            bsl::safe_umx const &pas) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_umx physbase{};
            bsl::safe_umx physmask{};

            constexpr auto msrs_per_iteration{bsl::to_u32(2)};
            for (bsl::safe_idx i{}; i < (vcnt * msrs_per_iteration); i += msrs_per_iteration) {
                auto mtrrphysbasen{MTRRPHYSBASE + i};
                auto mtrrphysmaskn{MTRRPHYSMASK + i};

                ret = syscall::bf_intrinsic_op_rdmsr(handle, mtrrphysmaskn, physmask);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                if (!this->physmask_to_valid(physmask)) {
                    continue;
                }

                ret = syscall::bf_intrinsic_op_rdmsr(handle, mtrrphysbasen, physbase);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                auto const addr{this->physbase_to_addr(physbase)};
                auto const size{this->physmask_to_size(physmask, pas)};
                auto const type{this->physbase_to_type(physbase)};

                ret = this->add_range(addr, size, type);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

    public:
        /// <!-- description -->
        ///   @brief Parses the MTRRs and stores the ranges in a continuous
        ///     non-overlapping form. This ensures that every single physical
        ///     address can be looked up by this class and provide the MTRR's
        ///     opinion as to what the memory's type is.
        ///
        /// <!-- inputs/outputs -->
        ///   @param handle the handle to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        [[nodiscard]] constexpr auto
        parse(syscall::bf_handle_t &handle) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            bsl::safe_umx rax{};
            bsl::safe_umx rbx{};
            bsl::safe_umx rcx{};
            bsl::safe_umx rdx{};

            /// NOTE:
            /// - Before we start, we need to ensure that the ranges are
            ///   cleared and an invalid state. This will ensure that during
            ///   the sorting process, ranges that are not used are ordered
            ///   last in the list.
            ///

            for (auto &mut_range : m_ranges) {
                mut_range = {
                    bsl::safe_umx::failure(),
                    bsl::safe_umx::failure(),
                    bsl::safe_umx::failure(),
                    false};
            }

            m_ranges_count = {};

            /// NOTE:
            /// - The first step is to get the total number of physical address
            ///   bits the hardware supports. This is needed to convert
            ///   the variable range registers.
            ///

            rax = CPUID_LP_ADDRESS_SIZE;
            rcx = {};
            intrinsic_cpuid(rax.data(), rbx.data(), rcx.data(), rdx.data());

            auto const pas{rax & CPUID_LP_ADDRESS_SIZE_PHYS_ADDR_BITS};
            auto const pas_bytes{bsl::ONE_UMAX << pas};

            /// NOTE:
            /// - The next step is to make sure that MTRRs are supported.
            ///   If they aren't something really weird is going on, but in
            ///   general, that is ok as all we have to do is add a single
            ///   range that marks all of memory as WB.
            ///

            rax = CPUID_FEATURE_IDENTIFIERS;
            rcx = {};
            intrinsic_cpuid(rax.data(), rbx.data(), rcx.data(), rdx.data());

            if ((rdx & CPUID_FEATURE_IDENTIFIERS_MTRR).is_zero()) {
                ret = this->add_range({bsl::ZERO_UMAX, pas_bytes, MEMORY_TYPE_WB, false});
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                return bsl::errc_success;
            }

            /// NOTE:
            /// - The next step is to get the MTRR information from the MSRs.
            ///   We have to ask the kernel for this information.
            ///

            bsl::safe_umx cap{};
            bsl::safe_umx deftype{};

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRCAP, cap);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = syscall::bf_intrinsic_op_rdmsr(handle, MTRRDEFTYPE, deftype);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const cap_vcnt{bsl::to_u32(cap & MTRRCAP_VCNT)};
            auto const cap_fix{bsl::to_u32(cap & MTRRCAP_FIX)};

            auto const deftype_type{deftype & MTRRDEFTYPE_TYPE};
            auto const deftype_fe{deftype & MTRRDEFTYPE_FE};
            auto const deftype_e{deftype & MTRRDEFTYPE_E};

            /// NOTE:
            /// - If the MTRRs are disabled, the default memory type is
            ///   uncacheable.
            ///

            if (deftype_e.is_zero()) {
                ret = this->add_range({bsl::ZERO_UMAX, pas_bytes, MEMORY_TYPE_UC, false});
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                return bsl::errc_success;
            }

            /// NOTE:
            /// - Next we need to add the default range to the list. This sets
            ///   all of memory to this memory type. All calls to add_range()
            ///   after this will split this default type up for each memory
            ///   type defined by BIOS. This ensures that when we are done,
            ///   every physical memory address has a type defined for it.
            /// - It should be noted that the add_range() algorithm expects
            ///   that this initial range is added for it work properly.
            ///

            ret = this->add_range({bsl::ZERO_UMAX, pas_bytes, deftype_type, true});
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            /// NOTE:
            /// - Next, let's add the fixed range MTRRs.
            ///

            if (cap_fix.is_pos()) {
                if (deftype_fe.is_pos()) {
                    ret = this->add_mtrr_fix64k_00000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    ret = this->add_mtrr_fix16k_80000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    ret = this->add_mtrr_fix16k_a0000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    ret = this->add_mtrr_fix4k_c0000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    ret = this->add_mtrr_fix4k_c8000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    ret = this->add_mtrr_fix4k_d0000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    ret = this->add_mtrr_fix4k_d8000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    ret = this->add_mtrr_fix4k_e0000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    ret = this->add_mtrr_fix4k_e8000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    ret = this->add_mtrr_fix4k_f0000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    ret = this->add_mtrr_fix4k_f8000(handle);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    bsl::touch();
                }
                else {
                    bsl::touch();
                }
            }
            else {
                bsl::touch();
            }

            ret = this->add_variable_range(handle, cap_vcnt, pas);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            this->compress_ranges();

            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Creates an identity map in the provided map using the
        ///     memory types contained in the MTRRs. The resulting identity
        ///     map will mimic the MTRRs given the range provided
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam MAP_T the type of map to use
        ///   @param map the map to create the identity map in
        ///   @param gpa the starting guest physical address
        ///   @param size the number of bytes from the provided gpa to map
        ///   @param flags the read/write/execute flags to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        template<typename MAP_T>
        [[nodiscard]] constexpr auto
        identity_map_4k(
            MAP_T &map,
            bsl::safe_umx const &gpa,
            bsl::safe_umx const &size,
            bsl::safe_umx const &flags) noexcept -> bsl::errc_type
        {
            constexpr bsl::safe_u64 page_size_4k{bsl::to_umx(0x001000U)};

            bsl::errc_type ret{};
            bsl::safe_umx crsr{gpa};

            if (bsl::unlikely(!gpa)) {
                bsl::error() << "guest physical address is invalid: "    // --
                             << bsl::hex(gpa)                            // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_4k_aligned(gpa))) {
                bsl::error() << "guest physical address is not 2m page aligned: "    // --
                             << bsl::hex(gpa)                                        // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!size)) {
                bsl::error() << "size is invalid: "    // --
                             << bsl::hex(size)         // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_4k_aligned(size))) {
                bsl::error() << "size is not 2m page aligned: "    // --
                             << bsl::hex(size)                     // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < m_ranges_count; ++i) {
                auto *const range{m_ranges.at_if(i)};

                if (range->addr + range->size < crsr) {
                    continue;
                }

                while (crsr < range->addr + range->size) {

                    if (!(crsr < gpa + size)) {
                        return bsl::errc_success;
                    }

                    ret = map.map_4k_page(crsr, crsr, flags, range->type);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return ret;
                    }

                    crsr += page_size_4k;
                }
            }

            bsl::error() << "identity map is out of bounds"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Creates an identity map in the provided map using the
        ///     memory types contained in the MTRRs. The resulting identity
        ///     map will mimic the MTRRs given the range provided
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam MAP_T the type of map to use
        ///   @param map the map to create the identity map in
        ///   @param gpa the starting guest physical address
        ///   @param size the number of bytes from the provided gpa to map
        ///   @param flags the read/write/execute flags to use
        ///   @return Returns bsl::errc_success on success and bsl::errc_failure
        ///     on failure.
        ///
        template<typename MAP_T>
        [[nodiscard]] constexpr auto
        identity_map_2m(
            MAP_T &map,
            bsl::safe_umx const &gpa,
            bsl::safe_umx const &size,
            bsl::safe_umx const &flags) noexcept -> bsl::errc_type
        {
            constexpr bsl::safe_u64 page_size_4k{bsl::to_umx(0x001000U)};
            constexpr bsl::safe_u64 page_size_2m{bsl::to_umx(0x200000U)};

            bsl::errc_type ret{};
            bsl::safe_umx crsr{gpa};

            if (bsl::unlikely(!gpa)) {
                bsl::error() << "guest physical address is invalid: "    // --
                             << bsl::hex(gpa)                            // --
                             << bsl::endl                                // --
                             << bsl::here();                             // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_2m_aligned(gpa))) {
                bsl::error() << "guest physical address is not 2m page aligned: "    // --
                             << bsl::hex(gpa)                                        // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!size)) {
                bsl::error() << "size is invalid: "    // --
                             << bsl::hex(size)         // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->is_page_2m_aligned(size))) {
                bsl::error() << "size is not 2m page aligned: "    // --
                             << bsl::hex(size)                     // --
                             << bsl::endl                          // --
                             << bsl::here();                       // --

                return bsl::errc_failure;
            }

            for (bsl::safe_idx i{}; i < m_ranges_count; ++i) {
                auto *const range{m_ranges.at_if(i)};

                if (range->addr + range->size < crsr) {
                    continue;
                }

                while (crsr < range->addr + range->size) {

                    if (!(crsr < gpa + size)) {
                        return bsl::errc_success;
                    }

                    if (this->is_page_2m_aligned(crsr)) {
                        if (!(crsr + page_size_2m > range->addr + range->size)) {

                            ret = map.map_2m_page(crsr, crsr, flags, range->type);
                            if (bsl::unlikely(!ret)) {
                                bsl::print<bsl::V>() << bsl::here();
                                return ret;
                            }

                            crsr += page_size_2m;
                            continue;
                        }

                        bsl::touch();
                    }
                    else {
                        bsl::touch();
                    }

                    ret = map.map_4k_page(crsr, crsr, flags, range->type);
                    if (bsl::unlikely(!ret)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return ret;
                    }

                    crsr += page_size_4k;
                }
            }

            if (crsr == gpa + size) {
                return bsl::errc_success;
            }

            bsl::error() << "identity map is out of bounds"    // --
                         << bsl::endl                          // --
                         << bsl::here();                       // --

            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Returns the max physical address in the MTRRs on success,
        ///     or bsl::safe_umx::failure() on failure.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the max physical address in the MTRRs on success,
        ///     or bsl::safe_umx::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        max_phys() noexcept -> bsl::safe_umx
        {
            if (m_ranges_count.is_zero()) {
                bsl::error() << "mtrrs has not been parsed yet\n" << bsl::here();
                return bsl::safe_umx::failure();
            }

            auto const *const range{m_ranges.at_if(m_ranges_count - bsl::ONE_UMAX)};
            return range->addr + range->size;
        }

        /// <!-- description -->
        ///   @brief Outputs the contents of the MTRRs.
        ///
        constexpr void
        dump() const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            bsl::print() << bsl::mag << "mtrrs dump: ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Header
            ///

            bsl::print() << bsl::ylw << "+------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^19s", "start "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^19s", "end "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^5s", "type "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            /// MTRRs
            ///

            for (bsl::safe_idx i{}; i < m_ranges_count; ++i) {
                auto const *rowcolor{bsl::rst};
                auto const *const range{m_ranges.at_if(i)};

                bsl::safe_umx const srt{range->addr};
                bsl::safe_umx const end{range->addr + range->size - bsl::ONE_UMAX};

                if (MEMORY_TYPE_UC == range->type) {
                    rowcolor = bsl::blk;
                }
                else {
                    bsl::touch();
                }

                bsl::print() << bsl::ylw << "| ";
                bsl::print() << rowcolor << bsl::hex(srt) << ' ';
                bsl::print() << bsl::ylw << "| ";
                bsl::print() << rowcolor << bsl::hex(end) << ' ';
                bsl::print() << bsl::ylw << "| ";

                switch (range->type.get()) {
                    case MEMORY_TYPE_WC.get(): {
                        bsl::print() << rowcolor << bsl::fmt{"^5s", "wc"};
                        break;
                    }

                    case MEMORY_TYPE_WP.get(): {
                        bsl::print() << rowcolor << bsl::fmt{"^5s", "wp"};
                        break;
                    }

                    case MEMORY_TYPE_WT.get(): {
                        bsl::print() << rowcolor << bsl::fmt{"^5s", "wt"};
                        break;
                    }

                    case MEMORY_TYPE_WB.get(): {
                        bsl::print() << rowcolor << bsl::fmt{"^5s", "wb"};
                        break;
                    }

                    default: {
                        bsl::print() << rowcolor << bsl::fmt{"^5s", "uc"};
                        break;
                    }
                }

                bsl::print() << bsl::ylw << "| ";
                bsl::print() << bsl::rst << bsl::endl;
            }

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;
        }
    };
}

#endif
