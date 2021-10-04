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

#ifndef DISPATCH_VMEXIT_NMI_WINDOW_HPP
#define DISPATCH_VMEXIT_NMI_WINDOW_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>

namespace syscall
{
    /// <!-- description -->
    ///   @brief Handle NMIs Windows
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] static constexpr auto
    dispatch_vmexit_nmi_window(
        gs_t const &gs, tls_t const &tls, bf_syscall_t &mut_sys, bsl::safe_u16 const &vsid) noexcept
        -> bsl::errc_type
    {
        constexpr auto nmi_info{0x80000202_u64};
        constexpr auto vmcs_clear_nmi_window_exiting{0xFFBFFFFF_u64};
        constexpr auto ctls_idx{bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls};
        constexpr auto info_idx{bf_reg_t::bf_reg_t_vmentry_interrupt_information_field};

        bsl::discard(gs);
        bsl::discard(tls);

        /// NOTE:
        /// - If we see this exit, it is because an NMI fired. There are two
        ///   situations where this could occur, either while the hypervisor
        ///   is running, or the VS is running. In either case, we need to
        ///   clear the NMI window and inject the NMI into the appropriate
        ///   VS so that it can be handled. Note that Intel requires that
        ///   we handle NMIs, and they actually happen a lot with Linux based
        ///   on what hardware you are using (e.g., a laptop).
        ///

        auto mut_val{mut_sys.bf_vs_op_read(vsid, ctls_idx)};
        bsl::expects(mut_val.is_valid_and_checked());

        mut_val &= vmcs_clear_nmi_window_exiting;
        bsl::expects(mut_sys.bf_vs_op_write(vsid, ctls_idx, mut_val));

        /// NOTE:
        /// - Inject an NMI. If the NMI window was enabled, it is because we
        ///   need to inject a NMI. Note that the NMI window can be enabled
        ///   both by this extension, as well as by the microkernel itself,
        ///   so we are required to implement it on Intel.
        ///

        bsl::expects(mut_sys.bf_vs_op_write(vsid, info_idx, nmi_info));
        return mut_sys.bf_vs_op_run_current();
    }
}

#endif
