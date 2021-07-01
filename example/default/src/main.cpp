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

#include <bf_control_ops.hpp>
#include <bf_syscall_t.hpp>
#include <bootstrap_t.hpp>
#include <fail_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vmexit_t.hpp>
#include <vp_pool_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/unlikely_assert.hpp>

namespace example
{
    /// NOTE:
    /// - This is where we store all of our global and thread local variables.
    ///   All of the variables are marked as static to ensure they are not
    ///   visable to the rest of the code.
    /// - All global and thread local variables must be passed around from
    ///   function to function as needed. This ensures that constexpr unit
    ///   tests work properly as the rest of the code never relies on global
    ///   variables. In addition, it dramatically simplifies unit testing, so
    ///   enforcing this coding style, although annoying for the function
    ///   signatures, makes working with the rest of the code a lot easier.
    /// - We use constinit here, which works around a specific AUTOSAR rule
    ///   that does not allow global constructors/destructors. By using
    ///   constinit, we are sure that runtime global constructors are not used.
    ///   Bareflank does not attempt to run any init/fini sections of the
    ///   ELF binary, so if you use accidentally forget constinit, the code
    ///   will likely not execute and fail as a reminder. Instead, use the
    ///   initialization/release pattern that this example provides.
    /// - From a unit testing point of view, each of these will have dummy
    ///   versions that are used for testing. When the code is compiled, each
    ///   source file and head file is compiled in isolation, meaning they are
    ///   not given include folder access to all of the code. This means that
    ///   each of these must be mocked, and the unit tests are given include
    ///   access to the mocks. This prevents the need for templates, and
    ///   instead, all mock injection is done using the build system, greatly
    ///   simplifying both the code and branch analysis during unit tests as
    ///   the removal of templates also removes issues with branches being
    ///   counted for each instantiaion of a template type.
    /// - Finally, some of these are not really needed for this simple example,
    ///   but we added them for completness so that it is easier to get
    ///   started with your own extension as more complicated code will likely
    ///   need most of these if not all.
    ///

    /// @brief stores the bf_syscall_t that this code will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit syscall::bf_syscall_t g_mut_sys{};
    /// @brief stores the intrinsic_t that this code will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit intrinsic_t g_mut_intrinsic{};

    /// @brief stores the pool of VPs that we will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit vp_pool_t g_mut_vp_pool{};
    /// @brief stores the pool of VPSs that we will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit vps_pool_t g_mut_vps_pool{};

    /// @brief stores the bootstrap_t that this code will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit bootstrap_t g_mut_bootstrap{};
    /// @brief stores the fail_t that this code will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit fail_t g_mut_fail{};
    /// @brief stores the vmexit_t that this code will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit vmexit_t g_mut_vmexit{};

    /// @brief stores the Global Storage for this extension
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit gs_t g_mut_gs{};
    /// @brief stores the Thread Local Storage for this extension on this PP
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    thread_local tls_t g_mut_tls{};

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
        /// NOTE:
        /// - Call into the bootstrap handler. This entry point serves as a
        ///   trampoline between C and C++. Specifically, the microkernel
        ///   cannot call a member function directly, and can only call
        ///   a C style function.
        ///

        auto const ret{g_mut_bootstrap.dispatch(    // --
            g_mut_gs,                               // --
            g_mut_tls,                              // --
            g_mut_sys,                              // --
            g_mut_intrinsic,                        // --
            g_mut_vp_pool,                          // --
            g_mut_vps_pool,                         // --
            bsl::to_u16(ppid))};

        if (bsl::unlikely_assert(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - This code should never be reached. The bootstrap handler should
        ///   always call one of the "run" ABIs to return back to the
        ///   microkernel when a bootstrap is finished. If this is called, it
        ///   is because the bootstrap handler returned with an error.
        ///

        return syscall::bf_control_op_exit();
    }

    /// <!-- description -->
    ///   @brief Implements the fast fail entry function. This is registered
    ///     by the main function to execute whenever a fast fail occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpsid the ID of the VPS that generated the fail
    ///   @param fail_reason the exit reason associated with the fail
    ///
    extern "C" void
    fail_entry(
        syscall::bf_uint16_t::value_type const vpsid,
        syscall::bf_status_t::value_type const fail_reason) noexcept
    {
        /// NOTE:
        /// - Call into the fast fail handler. This entry point serves as a
        ///   trampoline between C and C++. Specifically, the microkernel
        ///   cannot call a member function directly, and can only call
        ///   a C style function.
        ///

        auto const ret{g_mut_fail.dispatch(    // --
            g_mut_gs,                          // --
            g_mut_tls,                         // --
            g_mut_sys,                         // --
            g_mut_intrinsic,                   // --
            g_mut_vp_pool,                     // --
            g_mut_vps_pool,                    // --
            bsl::to_u16(vpsid),                // --
            bsl::to_u64(fail_reason))};

        if (bsl::unlikely_assert(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - This code should never be reached. The fast fail handler should
        ///   always call one of the "run" ABIs to return back to the
        ///   microkernel when a fast fail is finished. If this is called, it
        ///   is because the fast fail handler returned with an error.
        ///

        return syscall::bf_control_op_exit();
    }

    /// <!-- description -->
    ///   @brief Implements the VMExit entry function. This is registered
    ///     by the main function to execute whenever a VMExit occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpsid the ID of the VPS that generated the VMExit
    ///   @param exit_reason the exit reason associated with the VMExit
    ///
    extern "C" void
    vmexit_entry(
        syscall::bf_uint16_t::value_type const vpsid,
        syscall::bf_uint64_t::value_type const exit_reason) noexcept
    {
        /// NOTE:
        /// - Call into the vmexit handler. This entry point serves as a
        ///   trampoline between C and C++. Specifically, the microkernel
        ///   cannot call a member function directly, and can only call
        ///   a C style function.
        ///

        auto const ret{g_mut_vmexit.dispatch(    // --
            g_mut_gs,                            // --
            g_mut_tls,                           // --
            g_mut_sys,                           // --
            g_mut_intrinsic,                     // --
            g_mut_vp_pool,                       // --
            g_mut_vps_pool,                      // --
            bsl::to_u16(vpsid),                  // --
            bsl::to_u64(exit_reason))};

        if (bsl::unlikely_assert(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - This code should never be reached. The VMExit handler should
        ///   always call one of the "run" ABIs to return back to the
        ///   microkernel when a VMExit is finished. If this is called, it
        ///   is because the VMExit handler returned with an error.
        ///

        return syscall::bf_control_op_exit();
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
        bsl::errc_type mut_ret{};

        /// NOTE:
        /// - Initialize the bf_syscall_t. This will validate the ABI version,
        ///   open a handle to the microkernel and register the required
        ///   callbacks. If this fails, we call bf_control_op_exit, which is
        ///   similar to exit() from POSIX, except that the return value is
        ///   always the same.
        ///

        mut_ret = g_mut_sys.initialize(    // --
            bsl::to_u32(version),          // --
            &bootstrap_entry,              // --
            &vmexit_entry,                 // --
            &fail_entry);                  // --

        if (bsl::unlikely_assert(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Initialize the g_mut_intrinsic. This can be used to add any init
        ///   logic that might be needed, otherwise it can be removed.
        ///

        mut_ret = g_mut_intrinsic.initialize(g_mut_gs, g_mut_tls);
        if (bsl::unlikely_assert(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Initialize the vp_pool_t. This will give all of our vp_t's
        ///   their IDs so that they can be allocated.
        ///

        mut_ret = g_mut_vp_pool.initialize(g_mut_gs, g_mut_tls, g_mut_sys, g_mut_intrinsic);
        if (bsl::unlikely_assert(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Initialize the vps_pool_t. This will give all of our vps_t's
        ///   their IDs so that they can be allocated.
        ///

        mut_ret = g_mut_vps_pool.initialize(g_mut_gs, g_mut_tls, g_mut_sys, g_mut_intrinsic);
        if (bsl::unlikely_assert(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Initialize the g_mut_bootstrap. This can be used to add any init
        ///   logic that might be needed, otherwise it can be removed.
        ///

        mut_ret = g_mut_bootstrap.initialize(
            g_mut_gs, g_mut_tls, g_mut_sys, g_mut_intrinsic, g_mut_vp_pool, g_mut_vps_pool);
        if (bsl::unlikely_assert(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Initialize the g_mut_fail. This can be used to add any init
        ///   logic that might be needed, otherwise it can be removed.
        ///

        mut_ret = g_mut_fail.initialize(
            g_mut_gs, g_mut_tls, g_mut_sys, g_mut_intrinsic, g_mut_vp_pool, g_mut_vps_pool);
        if (bsl::unlikely_assert(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Initialize the g_mut_vmexit. This can be used to add any init
        ///   logic that might be needed, otherwise it can be removed.
        ///

        mut_ret = g_mut_vmexit.initialize(
            g_mut_gs, g_mut_tls, g_mut_sys, g_mut_intrinsic, g_mut_vp_pool, g_mut_vps_pool);
        if (bsl::unlikely_assert(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Wait for callbacks. Note that this function does not return.
        ///   The next time the extension is executed, it will be the
        ///   bootstrap callback that was just previously registered, which
        ///   will be called on each PP that is online. Failure to call this
        ///   function leads to undefined behaviour (likely a page fault).
        /// - This is similar to the wait() function from POSIX after having
        ///   just started some processes, with the difference being that
        ///   this will never return, so there is no need to pass in status
        ///   as there is nothing to process after this call.
        ///

        return syscall::bf_control_op_wait();
    }
}
