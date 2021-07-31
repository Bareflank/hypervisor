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
#include <vs_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace integration
{
    /// @class integration::bootstrap_t
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
        ///   @param vs_pool the vs_pool_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        initialize(
            gs_t &gs,
            tls_t &tls,
            syscall::bf_syscall_t &sys,
            intrinsic_t &intrinsic,
            vp_pool_t &vp_pool,
            vs_pool_t &vs_pool) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);
            bsl::discard(vp_pool);
            bsl::discard(vs_pool);

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
        ///   @param vs_pool the vs_pool_t to use
        ///
        static constexpr void
        release(
            gs_t &gs,
            tls_t &tls,
            syscall::bf_syscall_t &sys,
            intrinsic_t &intrinsic,
            vp_pool_t &vp_pool,
            vs_pool_t &vs_pool) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);
            bsl::discard(vp_pool);
            bsl::discard(vs_pool);
        }

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
        [[nodiscard]] static constexpr auto
        dispatch(
            gs_t &gs,
            tls_t &tls,
            syscall::bf_syscall_t &sys,
            intrinsic_t &intrinsic,
            vp_pool_t &vp_pool,
            vs_pool_t &vs_pool,
            bsl::safe_u16 const &ppid) noexcept -> bsl::errc_type
        {
            auto const vmid{syscall::BF_ROOT_VMID};

            auto mut_vpid{vp_pool.allocate(gs, tls, sys, intrinsic, vmid, ppid)};
            if (bsl::unlikely(!mut_vpid)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto mut_vsid{vs_pool.allocate(gs, tls, sys, intrinsic, mut_vpid, ppid)};
            if (bsl::unlikely(!mut_vsid)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            return sys.bf_vs_op_run(vmid, mut_vpid, mut_vsid);
        }
    };
}

#endif
