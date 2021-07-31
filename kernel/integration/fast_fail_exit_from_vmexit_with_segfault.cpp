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

#include "integration_utils.hpp"

#include <bf_control_ops.hpp>
#include <bf_syscall_t.hpp>
#include <bootstrap_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/debug.hpp>

namespace integration
{
    /// @brief stores the bf_syscall_t that this code will use
    constinit syscall::bf_syscall_t g_sys{};
    /// @brief stores the intrinsic_t that this code will use
    constinit intrinsic_t g_intrinsic{};

    /// @brief stores the pool of VPs that we will use
    constinit vp_pool_t g_vp_pool{};
    /// @brief stores the pool of VSs that we will use
    constinit vs_pool_t g_vs_pool{};

    /// @brief stores the bootstrap_t that this code will use
    constinit bootstrap_t g_bootstrap{};

    /// @brief stores the Global Storage for this extension
    constinit gs_t g_gs{};
    /// @brief stores the Thread Local Storage for this extension on this PP
    thread_local tls_t g_tls{};

    /// <!-- description -->
    ///   @brief Implements the bootstrap entry function. This function is
    ///     called on each PP while the hypervisor is being bootstrapped.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ppid the physical process to bootstrap
    ///
    extern "C" void
    bootstrap_entry(syscall::bf_uint16_t::value_type const ppid) noexcept
    {
        bsl::errc_type ret{};

        ret = g_bootstrap.dispatch(    // --
            g_gs,                      // --
            g_tls,                     // --
            g_sys,                     // --
            g_intrinsic,               // --
            g_vp_pool,                 // --
            g_vs_pool,                 // --
            bsl::to_u16(ppid));

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        return syscall::bf_control_op_exit();
    }

    /// <!-- description -->
    ///   @brief Implements the fast fail entry function. This is registered
    ///     by the main function to execute whenever a fast fail occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid the ID of the VS that generated the fail
    ///   @param fail_reason the exit reason associated with the fail
    ///
    extern "C" void
    fail_entry(
        syscall::bf_uint16_t::value_type const vsid,
        syscall::bf_status_t::value_type const fail_reason) noexcept
    {
        bsl::discard(vsid);
        bsl::discard(fail_reason);

        return syscall::bf_control_op_exit();
    }

    /// <!-- description -->
    ///   @brief Implements the VMExit entry function. This is registered
    ///     by the main function to execute whenever a VMExit occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @param exit_reason the exit reason associated with the VMExit
    ///
    extern "C" void
    vmexit_entry(
        syscall::bf_uint16_t::value_type const vsid,
        syscall::bf_uint64_t::value_type const exit_reason) noexcept
    {
        bsl::discard(vsid);
        bsl::discard(exit_reason);

        bsl::error() << "extension purposely dereferencing nullptr. fault expected\n";
        bool *i{};
        // This is intentional as it is what we are testing.
        // NOLINTNEXTLINE(clang-analyzer-core.NullDereference)
        *i = true;
    }

    /// <!-- description -->
    ///   @brief Implements the main entry function for this example
    ///
    /// <!-- inputs/outputs -->
    ///   @param version the version of the spec implemented by the
    ///     microkernel. This can be used to ensure the extension and the
    ///     microkernel speak the same ABI.
    ///
    extern "C" void
    ext_main_entry(bsl::uint32 const version) noexcept
    {
        bsl::errc_type ret{};

        ret = g_sys.initialize(bsl::to_u32(version), &bootstrap_entry, &vmexit_entry, &fail_entry);
        integration::require_success(ret);

        ret = g_intrinsic.initialize(g_gs, g_tls);
        integration::require_success(ret);

        ret = g_vp_pool.initialize(g_gs, g_tls, g_sys, g_intrinsic);
        integration::require_success(ret);

        ret = g_vs_pool.initialize(g_gs, g_tls, g_sys, g_intrinsic);
        integration::require_success(ret);

        ret = g_bootstrap.initialize(g_gs, g_tls, g_sys, g_intrinsic, g_vp_pool, g_vs_pool);
        integration::require_success(ret);

        return syscall::bf_control_op_wait();
    }
}
