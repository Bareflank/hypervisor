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

#ifndef BOOTSTRAP_T_HPP
#define BOOTSTRAP_T_HPP

#include <bf_constants.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely_assert.hpp>

namespace example
{
    /// @class example::bootstrap_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's bootstrap handler
    ///
    class bootstrap_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Initializes this bootstrap_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vps_pool the vps_pool_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            vp_pool_t const &vp_pool,
            vps_pool_t const &vps_pool) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);
            bsl::discard(vp_pool);
            bsl::discard(vps_pool);

            /// NOTE:
            /// - Add initialization code here if needed. Otherwise, this
            ///   function can be removed if it is not needed.
            ///

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the bootstrap_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vps_pool the vps_pool_t to use
        ///
        static constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            vp_pool_t const &vp_pool,
            vps_pool_t const &vps_pool) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);
            bsl::discard(vp_pool);
            bsl::discard(vps_pool);

            /// NOTE:
            /// - Release functions are usually only needed in the event of
            ///   an error, or during unit testing.
            ///
        }

        /// <!-- description -->
        ///   @brief Dispatches the bootstrap process as needed. Note that
        ///     the bootstrap callback is only called when starting the
        ///     hypervisor on root VPs.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param mut_vp_pool the vp_pool_t to use
        ///   @param mut_vps_pool the vps_pool_t to use
        ///   @param ppid the ID of the PP to bootstrap
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        dispatch(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            vp_pool_t &mut_vp_pool,
            vps_pool_t &mut_vps_pool,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::errc_type
        {
            /// NOTE:
            /// - In order to execcute bf_vps_op_run, which is what executes
            ///   the hypervisor, we must have a VM, VP and VPS.
            /// - The root VM is already created for us, so we don't need to
            ///   create this ourselves. You only need to create VM's if you
            ///   plan to add guest support with your extensions.
            ///

            auto const vmid{syscall::BF_ROOT_VMID};

            /// NOTE:
            /// - The VP in this simple example does nothing, but we still need
            ///   to create one. The VP is used when you have more than one VPS
            ///   per VP (e.g., if you are implementing HyperV's VSM, or nested
            ///   virtualization support). Otherwise, you will always have one
            ///   VPS for each VP, and they will appear as the same thing.
            /// - The VPS is what stores the state associated with the VPS. It
            ///   is the thing that does most of the work, including storing
            ///   the VMCS/VMCB and other CPU register state that is needed.
            ///

            auto const vpid{mut_vp_pool.allocate(gs, tls, mut_sys, intrinsic, vmid, ppid)};
            if (bsl::unlikely_assert(!vpid)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const vpsid{mut_vps_pool.allocate(gs, tls, mut_sys, intrinsic, vpid, ppid)};
            if (bsl::unlikely_assert(!vpsid)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            /// NOTE:
            /// - Run the newly created VP on behalf of the root VM using the
            ///   newly created and initialized VPS. Note that this version of
            ///   the run function should only be used when starting the
            ///   hypervisor, or switching the VM, VP or VPS as it is slow.
            ///

            return mut_sys.bf_vps_op_run(vmid, vpid, vpsid);
        }
    };
}

#endif
