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
///   @brief Handle NMIs Windows
///
/// <!-- inputs/outputs -->
///   @param gs the gs_t to use
///   @param tls the tls_t to use
///   @param sys the bf_syscall_t to use
///   @param vsid the ID of the VS that generated the VMExit
///   @return Returns bsl::errc_success on success, bsl::errc_failure
///     and friends otherwise
///
pub fn dispatch_vmexit_nmi_window(
    gs: &crate::GsT,
    tls: &crate::TlsT,
    sys: &mut syscall::BfSyscallT,
    vsid: bsl::SafeU16,
) -> bsl::ErrcType {
    let nmi_info = bsl::SafeU64::new(0x80000202);
    let vmcs_clear_nmi_window_exiting = bsl::SafeU64::new(0xFFBFFFFF);
    let ctls_idx = syscall::BF_REG_T_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS;
    let info_idx = syscall::BF_REG_T_VMENTRY_INTERRUPT_INFORMATION_FIELD;

    bsl::discard(gs);
    bsl::discard(tls);

    // NOTE:
    // - If we see this exit, it is because an NMI fired. There are two
    //   situations where this could occur, either while the hypervisor
    //   is running, or the VS is running. In either case, we need to
    //   clear the NMI window and inject the NMI into the appropriate
    //   VS so that it can be handled. Note that Intel requires that
    //   we handle NMIs, and they actually happen a lot with Linux based
    //   on what hardware you are using (e.g., a laptop).
    //

    let mut val = sys.bf_vs_op_read(vsid, ctls_idx);
    bsl::expects(val.is_valid_and_checked());

    val &= vmcs_clear_nmi_window_exiting;
    bsl::expects(sys.bf_vs_op_write(vsid, ctls_idx, val));

    // NOTE:
    // - Inject an NMI. If the NMI window was enabled, it is because we
    //   need to inject a NMI. Note that the NMI window can be enabled
    //   both by this extension, as well as by the microkernel itself,
    //   so we are required to implement it on Intel.
    //

    bsl::expects(sys.bf_vs_op_write(vsid, info_idx, nmi_info));
    return sys.bf_vs_op_run_current();
}
