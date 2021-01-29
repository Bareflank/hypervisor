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

#ifndef DISPATCH_ESR_NMI_HPP
#define DISPATCH_ESR_NMI_HPP

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides the main entry point for NMI exceptions.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam TLS_CONCEPT defines the type of TLS block to use
    ///   @tparam INTRINSIC_CONCEPT defines the type of intrinsics to use
    ///   @param tls the current TLS block
    ///   @param intrinsic the intrinsics to use
    ///   @return Returns bsl::exit_success if the exception was handled,
    ///     bsl::exit_failure otherwise
    ///
    template<typename TLS_CONCEPT, typename INTRINSIC_CONCEPT>
    [[nodiscard]] constexpr auto
    dispatch_esr_nmi(TLS_CONCEPT &tls, INTRINSIC_CONCEPT &intrinsic) noexcept -> bsl::exit_code
    {
        bsl::errc_type ret{};
        bsl::safe_uint32 val{};

        constexpr bsl::safe_uintmax vmcs_procbased_ctls_idx{bsl::to_umax(0x4002U)};
        constexpr bsl::safe_uint32 vmcs_set_nmi_window_exiting{bsl::to_u32(0x400000U)};

        if (bsl::ZERO_UMAX != tls.nmi_lock) {
            tls.nmi_pending = bsl::ONE_UMAX.get();
            return bsl::exit_success;
        }

        ret = intrinsic.vmread32(vmcs_procbased_ctls_idx, val.data());
        if (bsl::unlikely(!ret)) {
            bsl::error() << bsl::here();
            return bsl::exit_failure;
        }

        val |= vmcs_set_nmi_window_exiting;

        ret = intrinsic.vmwrite32(vmcs_procbased_ctls_idx, val);
        if (bsl::unlikely(!ret)) {
            bsl::error() << bsl::here();
            return bsl::exit_failure;
        }

        tls.nmi_pending = bsl::ZERO_UMAX.get();
        return bsl::exit_success;
    }
}

#endif
