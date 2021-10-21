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

/// <!-- description -->
///   @brief Handle NMIs. This is required by Intel.
///
/// <!-- inputs/outputs -->
///   @param gs the gs_t to use
///   @param tls the tls_t to use
///   @param sys the bf_syscall_t to use
///   @param vsid the ID of the VS that generated the VMExit
///   @return Returns bsl::errc_success on success, bsl::errc_failure
///     and friends otherwise
///
pub fn dispatch_vmexit_nmi(
    gs: &crate::GsT,
    tls: &crate::TlsT,
    sys: &mut syscall::BfSyscallT,
    vsid: bsl::SafeU16,
) -> bsl::ErrcType {
    let vmcs_set_nmi_window_exiting = bsl::SafeU64::new(0x400000);
    let ctls_idx = syscall::BF_REG_T_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS;

    bsl::discard(gs);
    bsl::discard(tls);

    // NOTE:
    // - If we caught an NMI, we need to inject it into the VM. To do
    //   this, all we do is enable the NMI window, which will tell us
    //   when we can safely inject the NMI.
    // - Note that the microkernel will do the same thing. If an NMI
    //   fires while the hypevisor is running, it will enable the NMI
    //   window, which the extension will see as a VMExit, and must
    //   from there, inject the NMI into the appropriate VS.
    //

    let mut val = sys.bf_vs_op_read(vsid, ctls_idx);
    bsl::expects(val.is_valid_and_checked());

    val |= vmcs_set_nmi_window_exiting;
    bsl::expects(sys.bf_vs_op_write(vsid, ctls_idx, val));

    return sys.bf_vs_op_run_current();
}
