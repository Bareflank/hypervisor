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

#ifndef DISPATCH_BOOTSTRAP
#define DISPATCH_BOOTSTRAP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_initialize.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// <!-- description -->
    ///   @brief Dispatches the bootstrap process as needed. Note that
    ///     the bootstrap callback is only called when starting the
    ///     hypervisor on root VPs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param mut_tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param mut_vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param ppid the ID of the PP to bootstrap
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] static constexpr auto
    dispatch_bootstrap(
        gs_t const &gs,
        tls_t &mut_tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        vp_pool_t &mut_vp_pool,
        vs_pool_t &mut_vs_pool,
        bsl::safe_u16 const &ppid) noexcept -> bsl::errc_type
    {
        bsl::expects(ppid.is_valid_and_checked());
        bsl::expects(ppid != syscall::BF_INVALID_ID);

        auto const ret{tls_initialize(mut_tls, mut_sys, intrinsic)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - In order to execcute bf_vs_op_run, which is what executes
        ///   the hypervisor, we must have a VM, VP and VS.
        /// - The root VM is already created for us, so we don't need to
        ///   create this ourselves. You only need to create VM's if you
        ///   plan to add guest support with your extensions.
        ///

        constexpr auto vmid{syscall::BF_ROOT_VMID};

        /// NOTE:
        /// - The VP in this simple example does nothing, but we still need
        ///   to create one. The VP is used when you have more than one VS
        ///   per VP (e.g., if you are implementing HyperV's VSM, or nested
        ///   virtualization support). Otherwise, you will always have one
        ///   VS for each VP, and they will appear as the same thing.
        /// - The VS is what stores the state associated with the VS. It
        ///   is the thing that does most of the work, including storing
        ///   the VMCS/VMCB and other CPU register state that is needed.
        ///

        auto const vpid{mut_vp_pool.allocate(gs, mut_tls, mut_sys, intrinsic, vmid, ppid)};
        if (bsl::unlikely(vpid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        auto const vsid{mut_vs_pool.allocate(gs, mut_tls, mut_sys, intrinsic, vpid, ppid)};
        if (bsl::unlikely(vsid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Run the newly created VP on behalf of the root VM using the
        ///   newly created and initialized VS. Note that this version of
        ///   the run function should only be used when starting the
        ///   hypervisor, or switching the VM, VP or VS as it is slow.
        ///

        return mut_sys.bf_vs_op_run(vmid, vpid, vsid);
    }
}

#endif
