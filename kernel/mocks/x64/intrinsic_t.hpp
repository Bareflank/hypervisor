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

#ifndef MOCKS_INTRINSIC_HPP
#define MOCKS_INTRINSIC_HPP

#include <bf_constants.hpp>

#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unordered_map.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides raw access to intrinsics. Instead of using global
    ///     functions, the intrinsics class provides a means for the rest of
    ///     the kernel to mock the intrinsics when needed during unit testing.
    ///
    class intrinsic_t final
    {
        /// @brief stores values associated with the TLS
        bsl::unordered_map<bsl::safe_u64, bsl::safe_u64> m_tlss{};
        /// @brief stores values associated with MSRs
        bsl::unordered_map<bsl::safe_u32, bsl::safe_u64> m_msrs{};

    public:
        /// <!-- description -->
        ///   @brief Invalidates TLB entries given an address and an ASID.
        ///     If the ASID is set to 0, an extension address is invalidated.
        ///     If the ASID is non-0, a guest address is invalidated using the
        ///     ASID. On AMD, this function does not invalidate an entire guest
        ///     VS (the vs_t must be used for that operation).
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to invalidate.
        ///   @param asid the ASID (as defined by AMD) to flush.
        ///
        static constexpr void
        tlb_flush(
            bsl::safe_u64 const &addr, bsl::safe_u16 const &asid = syscall::BF_INVALID_ID) noexcept
        {
            bsl::expects(addr.is_valid_and_checked());
            bsl::expects(addr.is_pos());
            bsl::expects(asid.is_valid_and_checked());
            bsl::expects(asid.is_pos());
        }

        /// <!-- description -->
        ///   @brief Sets the value of CR3
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set CR3 to
        ///
        static constexpr void
        set_rpt(bsl::safe_u64 const &val) noexcept
        {
            bsl::discard(val);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tp (TLS pointer)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set tp (TLS pointer) to
        ///
        static constexpr void
        set_tp(bsl::safe_u64 const &val) noexcept
        {
            bsl::discard(val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of a requested TLS register
        ///
        /// <!-- inputs/outputs -->
        ///   @param reg the TLS register to get
        ///   @return Returns the value of a requested TLS register
        ///
        [[nodiscard]] constexpr auto
        tls_reg(bsl::safe_u64 const &reg) const noexcept -> bsl::safe_u64
        {
            return m_tlss.at(reg);
        }

        /// <!-- description -->
        ///   @brief Sets the value of a requested TLS register
        ///
        /// <!-- inputs/outputs -->
        ///   @param reg the TLS register to set
        ///   @param val the value to set the TLS register to
        ///
        constexpr void
        set_tls_reg(bsl::safe_u64 const &reg, bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(reg.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            m_tlss.at(reg) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr the MSR to read from
        ///   @return Returns the value of requested MSR
        ///
        [[nodiscard]] constexpr auto
        rdmsr(bsl::safe_u32 const &msr) const noexcept -> bsl::safe_u64
        {
            bsl::expects(msr.is_valid_and_checked());

            if (msr == bsl::safe_u32::max_value()) {
                return bsl::safe_u64::failure();
            }

            return m_msrs.at(msr);
        }

        /// <!-- description -->
        ///   @brief Sets the value of requested MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr the MSR to write to
        ///   @param val the value to set the MSR to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        wrmsr(bsl::safe_u32 const &msr, bsl::safe_u64 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(msr.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            if (msr == bsl::safe_u32::max_value()) {
                return bsl::errc_failure;
            }

            m_msrs.at(msr) = val;
            return bsl::errc_success;
        }
    };
}

#endif
