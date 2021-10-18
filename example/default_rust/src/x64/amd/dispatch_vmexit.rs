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

const EXIT_REASON_CPUID: u64 = 0x72;

#[path = "../dispatch_vmexit_cpuid.rs"]
#[doc(hidden)]
pub mod dispatch_vmexit_cpuid;
pub use dispatch_vmexit_cpuid::*;

/// <!-- description -->
///   @brief Dispatches the VMExit.
///
/// <!-- inputs/outputs -->
///   @param gs the gs_t to use
///   @param tls the tls_t to use
///   @param sys the bf_syscall_t to use
///   @param intrinsic the intrinsic_t to use
///   @param vp_pool the vp_pool_t to use
///   @param vs_pool the vs_pool_t to use
///   @param vsid the ID of the VS that generated the VMExit
///   @param exit_reason the exit reason associated with the VMExit
///   @return Returns bsl::errc_success on success, bsl::errc_failure
///     and friends otherwise
///
pub fn dispatch_vmexit(
    gs: &crate::GsT,
    tls: &crate::TlsT,
    sys: &mut syscall::BfSyscallT,
    intrinsic: &crate::IntrinsicT,
    vp_pool: &crate::VpPoolT,
    vs_pool: &crate::VsPoolT,
    vsid: bsl::SafeU16,
    exit_reason: bsl::SafeU64,
) -> bsl::ErrcType {
    bsl::discard(vp_pool);
    bsl::discard(vs_pool);

    match exit_reason.get() {
        EXIT_REASON_CPUID => return crate::dispatch_vmexit_cpuid(gs, tls, sys, intrinsic, vsid),

        _ => {}
    }

    error!("unsupported vmexit: {:#018x}\n", exit_reason);
    syscall::bf_debug_op_dump_vs(vsid);
    print_v!("{}", bsl::here());

    return bsl::errc_failure;
}
