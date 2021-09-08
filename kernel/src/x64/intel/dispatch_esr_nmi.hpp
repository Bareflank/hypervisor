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

#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides the main entry point for NMI exceptions.
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///
    constexpr void
    dispatch_esr_nmi(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept
    {
        bsl::safe_u32 mut_val{};

        constexpr auto vmcs_procbased_ctls_idx{0x4002_umx};
        constexpr auto vmcs_set_nmi_window_exiting{0x400000_u32};

        if (bsl::safe_umx::magic_0() != mut_tls.nmi_lock) {
            mut_tls.nmi_pending = bsl::safe_umx::magic_1().get();
            return;
        }

        bsl::expects(mut_intrinsic.vmrd32(vmcs_procbased_ctls_idx, mut_val.data()));
        mut_val |= vmcs_set_nmi_window_exiting;
        bsl::expects(mut_intrinsic.vmwr32(vmcs_procbased_ctls_idx, mut_val));

        mut_tls.nmi_pending = bsl::safe_umx::magic_0().get();
    }
}

#endif
