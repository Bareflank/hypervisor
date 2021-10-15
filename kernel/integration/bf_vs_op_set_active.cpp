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
#include <dispatch_bootstrap.hpp>
#include <dispatch_fail.hpp>
#include <dispatch_vmexit.hpp>
#include <gs_initialize.hpp>
#include <gs_t.hpp>
#include <integration_utils.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace syscall
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
    ///   access to the MOCK. This prevents the need for templates, and
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
    constinit bf_syscall_t g_mut_sys{};
    /// @brief stores the intrinsic_t that this code will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit intrinsic_t g_mut_intrinsic{};

    /// @brief stores the pool of VPs that we will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit vp_pool_t g_mut_vp_pool{};
    /// @brief stores the pool of VSs that we will use
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit vs_pool_t g_mut_vs_pool{};

    /// @brief stores the Global Storage for this extension
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit gs_t g_mut_gs{};
    /// @brief stores the Thread Local Storage for this extension on this PP
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
    constinit thread_local tls_t g_mut_tls{};

    /// <!-- description -->
    ///   @brief Implements the bootstrap entry function. This function is
    ///     called on each PP while the hypervisor is being bootstrapped.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ppid0 the physical process to bootstrap
    ///
    extern "C" void
    bootstrap_entry(bsl::safe_u16::value_type const ppid0) noexcept
    {
        constexpr auto one{bsl::safe_u16::magic_1()};
        constexpr auto vmid0{bsl::safe_u16::magic_0()};
        constexpr auto ppid1{bsl::safe_u16::magic_1()};

        // invalid handle
        {
            constexpr auto hndl{BF_INVALID_HANDLE};
            bf_status_t const ret{bf_vs_op_set_active_impl(hndl.get(), {}, {}, {})};
            integration::require(ret != BF_STATUS_SUCCESS);
        }

        // invalid vmid
        {
            constexpr auto vmid{BF_INVALID_ID};
            bf_status_t const ret{bf_vs_op_set_active_impl({}, vmid.get(), {}, {})};
            integration::require(ret != BF_STATUS_SUCCESS);
        }

        // vmid out of range
        {
            constexpr auto vmid{(bsl::to_u16(HYPERVISOR_MAX_VSS) + one).checked()};
            bf_status_t const ret{bf_vs_op_set_active_impl({}, vmid.get(), {}, {})};
            integration::require(ret != BF_STATUS_SUCCESS);
        }

        // vmid never allocated
        {
            constexpr auto vmid{(bsl::to_u16(HYPERVISOR_MAX_VSS) - one).checked()};
            bf_status_t const ret{bf_vs_op_set_active_impl({}, vmid.get(), {}, {})};
            integration::require(ret != BF_STATUS_SUCCESS);
        }

        // invalid vpid
        {
            constexpr auto vpid{BF_INVALID_ID};
            bf_status_t const ret{bf_vs_op_set_active_impl({}, {}, vpid.get(), {})};
            integration::require(ret != BF_STATUS_SUCCESS);
        }

        // vpid out of range
        {
            constexpr auto vpid{(bsl::to_u16(HYPERVISOR_MAX_VSS) + one).checked()};
            bf_status_t const ret{bf_vs_op_set_active_impl({}, {}, vpid.get(), {})};
            integration::require(ret != BF_STATUS_SUCCESS);
        }

        // vpid never allocated
        {
            constexpr auto vpid{(bsl::to_u16(HYPERVISOR_MAX_VSS) - one).checked()};
            bf_status_t const ret{bf_vs_op_set_active_impl({}, {}, vpid.get(), {})};
            integration::require(ret != BF_STATUS_SUCCESS);
        }

        auto const vpid0{g_mut_sys.bf_vp_op_create_vp({})};
        integration::require(vpid0.is_valid());

        // invalid vsid
        {
            constexpr auto vsid{BF_INVALID_ID};
            bf_status_t const ret{bf_vs_op_set_active_impl({}, {}, vpid0.get(), vsid.get())};
            integration::require(ret != BF_STATUS_SUCCESS);
        }

        // vsid out of range
        {
            constexpr auto vsid{(bsl::to_u16(HYPERVISOR_MAX_VSS) + one).checked()};
            bf_status_t const ret{bf_vs_op_set_active_impl({}, {}, vpid0.get(), vsid.get())};
            integration::require(ret != BF_STATUS_SUCCESS);
        }

        // vsid never allocated
        {
            constexpr auto vsid{(bsl::to_u16(HYPERVISOR_MAX_VSS) - one).checked()};
            bf_status_t const ret{bf_vs_op_set_active_impl({}, {}, vpid0.get(), vsid.get())};
            integration::require(ret != BF_STATUS_SUCCESS);
        }

        auto const vsid0{g_mut_sys.bf_vs_op_create_vs(vpid0, bsl::to_u16(ppid0))};
        integration::require(vsid0.is_valid());

        // success
        {
            integration::require(g_mut_sys.bf_vs_op_set_active({}, vpid0, vsid0));
        }

        // success already active
        {
            integration::require(g_mut_sys.bf_vs_op_set_active({}, vpid0, vsid0));
        }

        auto const vmid1{g_mut_sys.bf_vm_op_create_vm()};
        integration::require(vmid1.is_valid());
        auto const vpid1{g_mut_sys.bf_vp_op_create_vp(vmid1)};
        integration::require(vpid1.is_valid());
        auto const vsid1{g_mut_sys.bf_vs_op_create_vs(vpid1, bsl::to_u16(ppid0))};
        integration::require(vsid1.is_valid());

        auto const vmid2{g_mut_sys.bf_vm_op_create_vm()};
        integration::require(vmid1.is_valid());
        auto const vpid2{g_mut_sys.bf_vp_op_create_vp(vmid2)};
        integration::require(vpid1.is_valid());
        auto const vsid2{g_mut_sys.bf_vs_op_create_vs(vpid2, bsl::to_u16(ppid1))};
        integration::require(vsid1.is_valid());

        // wrong ids
        {
            integration::require(!g_mut_sys.bf_vs_op_set_active(vmid1, vpid0, vsid0));
            integration::require(!g_mut_sys.bf_vs_op_set_active(vmid0, vpid1, vsid0));
            integration::require(!g_mut_sys.bf_vs_op_set_active(vmid2, vpid2, vsid2));
        }

        // make sure TLS switches correctly
        {
            using bf = syscall::bf_reg_t;
            constexpr auto expected1{0x1234567890ABCDEF_u64};
            constexpr auto expected2{0xFEDCBA0987654321_u64};

            integration::require(g_mut_sys.bf_vs_op_set_active(vmid0, vpid0, vsid0));
            g_mut_sys.bf_tls_set_rax(expected1);
            g_mut_sys.bf_tls_set_rbx(expected1);
            g_mut_sys.bf_tls_set_rcx(expected1);
            g_mut_sys.bf_tls_set_rdx(expected1);
            g_mut_sys.bf_tls_set_rbp(expected1);
            g_mut_sys.bf_tls_set_rsi(expected1);
            g_mut_sys.bf_tls_set_rdi(expected1);
            g_mut_sys.bf_tls_set_r8(expected1);
            g_mut_sys.bf_tls_set_r9(expected1);
            g_mut_sys.bf_tls_set_r10(expected1);
            g_mut_sys.bf_tls_set_r11(expected1);
            g_mut_sys.bf_tls_set_r12(expected1);
            g_mut_sys.bf_tls_set_r13(expected1);
            g_mut_sys.bf_tls_set_r14(expected1);
            g_mut_sys.bf_tls_set_r15(expected1);

            integration::require(g_mut_sys.bf_vs_op_set_active(vmid1, vpid1, vsid1));
            integration::require(expected1 != g_mut_sys.bf_tls_rax());
            integration::require(expected1 != g_mut_sys.bf_tls_rbx());
            integration::require(expected1 != g_mut_sys.bf_tls_rcx());
            integration::require(expected1 != g_mut_sys.bf_tls_rdx());
            integration::require(expected1 != g_mut_sys.bf_tls_rbp());
            integration::require(expected1 != g_mut_sys.bf_tls_rsi());
            integration::require(expected1 != g_mut_sys.bf_tls_rdi());
            integration::require(expected1 != g_mut_sys.bf_tls_r8());
            integration::require(expected1 != g_mut_sys.bf_tls_r9());
            integration::require(expected1 != g_mut_sys.bf_tls_r10());
            integration::require(expected1 != g_mut_sys.bf_tls_r11());
            integration::require(expected1 != g_mut_sys.bf_tls_r12());
            integration::require(expected1 != g_mut_sys.bf_tls_r13());
            integration::require(expected1 != g_mut_sys.bf_tls_r14());
            integration::require(expected1 != g_mut_sys.bf_tls_r15());

            g_mut_sys.bf_tls_set_rax(expected2);
            g_mut_sys.bf_tls_set_rbx(expected2);
            g_mut_sys.bf_tls_set_rcx(expected2);
            g_mut_sys.bf_tls_set_rdx(expected2);
            g_mut_sys.bf_tls_set_rbp(expected2);
            g_mut_sys.bf_tls_set_rsi(expected2);
            g_mut_sys.bf_tls_set_rdi(expected2);
            g_mut_sys.bf_tls_set_r8(expected2);
            g_mut_sys.bf_tls_set_r9(expected2);
            g_mut_sys.bf_tls_set_r10(expected2);
            g_mut_sys.bf_tls_set_r11(expected2);
            g_mut_sys.bf_tls_set_r12(expected2);
            g_mut_sys.bf_tls_set_r13(expected2);
            g_mut_sys.bf_tls_set_r14(expected2);
            g_mut_sys.bf_tls_set_r15(expected2);

            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_rax));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_rbx));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_rcx));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_rdx));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_rbp));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_rsi));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_rdi));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_r8));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_r9));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_r10));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_r11));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_r12));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_r13));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_r14));
            integration::require(expected1 == g_mut_sys.bf_vs_op_read(vsid0, bf::bf_reg_t_r15));

            integration::require(g_mut_sys.bf_vs_op_set_active(vmid0, vpid0, vsid0));

            integration::require(expected1 == g_mut_sys.bf_tls_rax());
            integration::require(expected1 == g_mut_sys.bf_tls_rbx());
            integration::require(expected1 == g_mut_sys.bf_tls_rcx());
            integration::require(expected1 == g_mut_sys.bf_tls_rdx());
            integration::require(expected1 == g_mut_sys.bf_tls_rbp());
            integration::require(expected1 == g_mut_sys.bf_tls_rsi());
            integration::require(expected1 == g_mut_sys.bf_tls_rdi());
            integration::require(expected1 == g_mut_sys.bf_tls_r8());
            integration::require(expected1 == g_mut_sys.bf_tls_r9());
            integration::require(expected1 == g_mut_sys.bf_tls_r10());
            integration::require(expected1 == g_mut_sys.bf_tls_r11());
            integration::require(expected1 == g_mut_sys.bf_tls_r12());
            integration::require(expected1 == g_mut_sys.bf_tls_r13());
            integration::require(expected1 == g_mut_sys.bf_tls_r14());
            integration::require(expected1 == g_mut_sys.bf_tls_r15());

            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_rax));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_rbx));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_rcx));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_rdx));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_rbp));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_rsi));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_rdi));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_r8));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_r9));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_r10));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_r11));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_r12));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_r13));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_r14));
            integration::require(expected2 == g_mut_sys.bf_vs_op_read(vsid1, bf::bf_reg_t_r15));
        }

        bsl::debug() << "success. remaining backtrace is expected\n" << bsl::here();
        return bf_control_op_exit();
    }

    /// <!-- description -->
    ///   @brief Implements the fast fail entry function. This is registered
    ///     by the main function to execute whenever a fast fail occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param errc the reason for the failure, which is CPU
    ///     specific. On x86, this is a combination of the exception
    ///     vector and error code.
    ///   @param addr contains a faulting address if the fail reason
    ///     is associated with an error that involves a faulting address (
    ///     for example like a page fault). Otherwise, the value of this
    ///     input is undefined.
    ///
    extern "C" void
    fail_entry(bsl::safe_u64::value_type const errc, bsl::safe_u64::value_type const addr) noexcept
    {
        /// NOTE:
        /// - Call into the fast fail handler. This entry point serves as a
        ///   trampoline between C and C++. Specifically, the microkernel
        ///   cannot call a member function directly, and can only call
        ///   a C style function.
        ///

        auto const ret{dispatch_fail(    // --
            g_mut_gs,                    // --
            g_mut_tls,                   // --
            g_mut_sys,                   // --
            g_mut_intrinsic,             // --
            g_mut_vp_pool,               // --
            g_mut_vs_pool,               // --
            bsl::to_u64(errc),           // --
            bsl::to_u64(addr))};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bf_control_op_exit();
        }

        /// NOTE:
        /// - This code should never be reached. The fast fail handler should
        ///   always call one of the "run" ABIs to return back to the
        ///   microkernel when a fast fail is finished. If this is called, it
        ///   is because the fast fail handler returned with an error.
        ///

        return bf_control_op_exit();
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
        bsl::safe_u16::value_type const vsid, bsl::safe_u64::value_type const exit_reason) noexcept
    {
        /// NOTE:
        /// - Call into the vmexit handler. This entry point serves as a
        ///   trampoline between C and C++. Specifically, the microkernel
        ///   cannot call a member function directly, and can only call
        ///   a C style function.
        ///

        auto const ret{dispatch_vmexit(    // --
            g_mut_gs,                      // --
            g_mut_tls,                     // --
            g_mut_sys,                     // --
            g_mut_intrinsic,               // --
            g_mut_vp_pool,                 // --
            g_mut_vs_pool,                 // --
            bsl::to_u16(vsid),             // --
            bsl::to_u64(exit_reason))};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bf_control_op_exit();
        }

        /// NOTE:
        /// - This code should never be reached. The VMExit handler should
        ///   always call one of the "run" ABIs to return back to the
        ///   microkernel when a VMExit is finished. If this is called, it
        ///   is because the VMExit handler returned with an error.
        ///

        return bf_control_op_exit();
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

        if (bsl::unlikely(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bf_control_op_exit();
        }

        mut_ret = gs_initialize(g_mut_gs, g_mut_sys, g_mut_intrinsic);
        if (bsl::unlikely(!mut_ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return bf_control_op_exit();
        }

        /// NOTE:
        /// - Initialize the vp_pool_t. This will give all of our vp_t's
        ///   their IDs so that they can be allocated.
        ///

        g_mut_vp_pool.initialize(g_mut_gs, g_mut_tls, g_mut_sys, g_mut_intrinsic);

        /// NOTE:
        /// - Initialize the vs_pool_t. This will give all of our vs_t's
        ///   their IDs so that they can be allocated.
        ///

        g_mut_vs_pool.initialize(g_mut_gs, g_mut_tls, g_mut_sys, g_mut_intrinsic);

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

        return bf_control_op_wait();
    }
}
