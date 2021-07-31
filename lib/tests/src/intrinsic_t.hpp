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

#ifndef MOCK_INTRINSIC_HPP
#define MOCK_INTRINSIC_HPP

#include <basic_tlb_flush_type_t.hpp>

#include <bsl/discard.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>

namespace lib
{
    /// @class lib::intrinsic_t
    ///
    /// <!-- description -->
    ///   @brief Provides raw access to intrinsics. Instead of using global
    ///     functions, the intrinsics class provides a means for the rest of
    ///     the kernel to mock the intrinsics when needed during unit testing.
    ///
    class intrinsic_t final
    {
        /// @brief stores the rpt
        bsl::safe_u64 m_rpt{};

    public:
        /// <!-- description -->
        ///   @brief Invalidates TLB entries given a address
        ///
        /// <!-- inputs/outputs -->
        ///   @param type determines which type of flush to perform
        ///   @param addr the address to invalidate
        ///   @param vmid if set to a valid ID, will flush the address for
        ///     the given VMID as an ASID.
        ///
        static constexpr void
        tlb_flush(
            basic_tlb_flush_type_t const type,
            bsl::safe_u64 const &addr,
            bsl::safe_u16 const &vmid = {}) noexcept
        {
            bsl::discard(type);
            bsl::expects(addr.is_valid_and_checked());
            bsl::expects(addr.is_pos());
            bsl::expects(vmid.is_valid_and_checked());
        }

        /// <!-- description -->
        ///   @brief Sets the RPT pointer
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set the RPT pointer to
        ///
        constexpr void
        set_rpt(bsl::safe_u64 const &val) noexcept
        {
            m_rpt = val;
        }

        /// <!-- description -->
        ///   @brief Returns the previously set RPT pointer
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the previously set RPT pointer
        ///
        [[nodiscard]] constexpr auto
        rpt() noexcept -> bsl::safe_u64
        {
            return m_rpt;
        }
    };
}

#endif
