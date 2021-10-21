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
///   @brief Dispatches the bootstrap process as needed. Note that
///     the bootstrap callback is only called when starting the
///     hypervisor on root VPs.
///
/// <!-- inputs/outputs -->
///   @param gs the gs_t to use
///   @param tls the tls_t to use
///   @param sys the bf_syscall_t to use
///   @param intrinsic the intrinsic_t to use
///   @param vp_pool the vp_pool_t to use
///   @param vs_pool the vs_pool_t to use
///   @param ppid the ID of the PP to bootstrap
///   @return Returns bsl::errc_success on success, bsl::errc_failure
///     and friends otherwise
///
pub fn dispatch_bootstrap(
    gs: &crate::GsT,
    tls: &mut crate::TlsT,
    sys: &mut syscall::BfSyscallT,
    intrinsic: &crate::IntrinsicT,
    vp_pool: &mut crate::VpPoolT,
    vs_pool: &mut crate::VsPoolT,
    ppid: bsl::SafeU16,
) -> bsl::ErrcType {
    bsl::expects(ppid.is_valid_and_checked());
    bsl::expects(ppid != syscall::BF_INVALID_ID);

    let ret = crate::tls_initialize(tls, sys, intrinsic);
    if !ret {
        print_v!("{}", bsl::here());
        return bsl::errc_failure;
    }

    // NOTE:
    // - In order to execcute bf_vs_op_run, which is what executes
    //   the hypervisor, we must have a VM, VP and VS.
    // - The root VM is already created for us, so we don't need to
    //   create this ourselves. You only need to create VM's if you
    //   plan to add guest support with your extensions.
    //

    let vmid = syscall::BF_ROOT_VMID;

    // NOTE:
    // - The VP in this simple example does nothing, but we still need
    //   to create one. The VP is used when you have more than one VS
    //   per VP (e.g., if you are implementing HyperV's VSM, or nested
    //   virtualization support). Otherwise, you will always have one
    //   VS for each VP, and they will appear as the same thing.
    // - The VS is what stores the state associated with the VS. It
    //   is the thing that does most of the work, including storing
    //   the VMCS/VMCB and other CPU register state that is needed.
    //

    let vpid = vp_pool.allocate(gs, tls, sys, intrinsic, vmid);
    if vpid.is_invalid() {
        print_v!("{}", bsl::here());
        return bsl::errc_failure;
    }

    let vsid = vs_pool.allocate(gs, tls, sys, intrinsic, vpid, ppid);
    if vsid.is_invalid() {
        print_v!("{}", bsl::here());
        return bsl::errc_failure;
    }

    // NOTE:
    // - Run the newly created VP on behalf of the root VM using the
    //   newly created and initialized VS. Note that this version of
    //   the run function should only be used when starting the
    //   hypervisor, or switching the VM, VP or VS as it is slow.
    //

    return sys.bf_vs_op_run(vmid, vpid, vsid);
}
