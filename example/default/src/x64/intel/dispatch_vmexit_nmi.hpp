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

#ifndef DISPATCH_VMEXIT_NMI_HPP
#define DISPATCH_VMEXIT_NMI_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>

namespace example
{
    /// <!-- description -->
    ///   @brief Handle NMIs. This is required by Intel.
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
    dispatch_vmexit_nmi(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        constexpr auto vmcs_set_nmi_window_exiting{0x400000_u64};
        constexpr auto ctls_idx{syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls};

        bsl::discard(gs);
        bsl::discard(tls);

        /// NOTE:
        /// - If we caught an NMI, we need to inject it into the VM. To do
        ///   this, all we do is enable the NMI window, which will tell us
        ///   when we can safely inject the NMI.
        /// - Note that the microkernel will do the same thing. If an NMI
        ///   fires while the hypevisor is running, it will enable the NMI
        ///   window, which the extension will see as a VMExit, and must
        ///   from there, inject the NMI into the appropriate VS.
        ///

        auto mut_val{mut_sys.bf_vs_op_read(vsid, ctls_idx)};
        bsl::expects(mut_val.is_valid_and_checked());

        mut_val |= vmcs_set_nmi_window_exiting;
        bsl::expects(mut_sys.bf_vs_op_write(vsid, ctls_idx, mut_val));

        return mut_sys.bf_vs_op_run_current();
    }
}

#endif
