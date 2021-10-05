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
#include <page_4k_t.hpp>
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
    ///   @param ppid the physical process to bootstrap
    ///
    extern "C" void
    bootstrap_entry(bsl::safe_u16::value_type const ppid) noexcept
    {
        bsl::discard(ppid);
        bf_status_t mut_ret{};

        // create with invalid handle
        {
            constexpr auto hndl{BF_INVALID_HANDLE};
            constexpr auto virt{HYPERVISOR_EXT_DIRECT_MAP_ADDR};

            mut_ret = bf_vm_op_unmap_direct_impl(hndl.get(), {}, virt.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);
        }

        // create with invalid vmid
        {
            constexpr auto virt{HYPERVISOR_EXT_DIRECT_MAP_ADDR};

            // BF_INVALID_ID
            mut_ret = bf_vm_op_unmap_direct_impl({}, BF_INVALID_ID.get(), virt.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // out of range
            auto const oor{bsl::to_u16(HYPERVISOR_MAX_VMS + bsl::safe_u64::magic_1()).checked()};
            mut_ret = bf_vm_op_unmap_direct_impl({}, oor.get(), virt.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // not yet created
            auto const nyc{bsl::to_u16(HYPERVISOR_MAX_VMS - bsl::safe_u64::magic_1()).checked()};
            mut_ret = bf_vm_op_unmap_direct_impl({}, nyc.get(), virt.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);
        }

        // create with invalid virt
        {
            // nullptr
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, {});
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // out of range
            auto const oor{0xFFFFFFFFFFFFF000_u64};
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, oor.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // unaligned address
            auto const uaa{0x42_u64};
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, uaa.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // HYPERVISOR_MK_STACK_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_MK_STACK_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // HYPERVISOR_MK_CODE_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_MK_CODE_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // HYPERVISOR_MK_PAGE_POOL_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_MK_PAGE_POOL_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // HYPERVISOR_MK_HUGE_POOL_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_MK_HUGE_POOL_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // HYPERVISOR_EXT_STACK_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_EXT_STACK_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // HYPERVISOR_EXT_FAIL_STACK_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_EXT_FAIL_STACK_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // HYPERVISOR_EXT_CODE_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_EXT_CODE_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // HYPERVISOR_EXT_TLS_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_EXT_TLS_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);
        }

        // nullptr (any address == HYPERVISOR_EXT_DIRECT_MAP_ADDR is a null phys)
        {
            // HYPERVISOR_EXT_DIRECT_MAP_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_EXT_DIRECT_MAP_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // HYPERVISOR_EXT_PAGE_POOL_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_EXT_PAGE_POOL_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);

            // HYPERVISOR_EXT_HUGE_POOL_ADDR
            mut_ret = bf_vm_op_unmap_direct_impl({}, {}, HYPERVISOR_EXT_HUGE_POOL_ADDR.get());
            integration::require(mut_ret != BF_STATUS_SUCCESS);
        }

        // never mapped
        {
            auto const phys{(HYPERVISOR_EXT_DIRECT_MAP_ADDR + HYPERVISOR_PAGE_SIZE).checked()};
            auto const *const virt{reinterpret_cast<page_4k_t const *>(phys.get())};    // NOLINT

            auto const ret{g_mut_sys.bf_vm_op_unmap_direct({}, virt)};
            integration::require(!ret);
        }

        // unmap the same address twice
        {
            constexpr auto phys{HYPERVISOR_PAGE_SIZE};

            auto const *const ptr{g_mut_sys.bf_vm_op_map_direct<page_4k_t>({}, phys)};
            integration::require(nullptr != ptr);

            auto const ret1{g_mut_sys.bf_vm_op_unmap_direct({}, ptr)};
            integration::require(ret1);

            auto const ret2{g_mut_sys.bf_vm_op_unmap_direct({}, ptr)};
            integration::require(!ret2);
        }

        // Map and then unmap a bunch of addresses
        {
            constexpr auto num_pages{0x5000_umx};

            for (bsl::safe_idx mut_i{bsl::safe_idx::magic_1()}; mut_i < num_pages; ++mut_i) {
                auto const phys{(HYPERVISOR_PAGE_SIZE * bsl::to_umx(mut_i)).checked()};

                auto const *const ptr{g_mut_sys.bf_vm_op_map_direct<page_4k_t>({}, phys)};
                integration::require(nullptr != ptr);

                auto const ret{g_mut_sys.bf_vm_op_unmap_direct({}, ptr)};
                integration::require(ret);
            }
        }

        // Do it again to make sure we can remap everything again
        {
            constexpr auto num_pages{0x5000_umx};

            for (bsl::safe_idx mut_i{bsl::safe_idx::magic_1()}; mut_i < num_pages; ++mut_i) {
                auto const phys{(HYPERVISOR_PAGE_SIZE * bsl::to_umx(mut_i)).checked()};

                auto const *const ptr{g_mut_sys.bf_vm_op_map_direct<page_4k_t>({}, phys)};
                integration::require(nullptr != ptr);

                auto const ret{g_mut_sys.bf_vm_op_unmap_direct({}, ptr)};
                integration::require(ret);
            }
        }

        // If the unmap is working, attempting to access a freed pointer should
        // segfault, which is how we will end this test.
        {
            bsl::debug() << "success. remaining fault is expected\n" << bsl::here();
            constexpr auto phys{HYPERVISOR_PAGE_SIZE};

            auto const *const ptr{g_mut_sys.bf_vm_op_map_direct<page_4k_t>({}, phys)};
            integration::require(nullptr != ptr);

            auto const ret{g_mut_sys.bf_vm_op_unmap_direct({}, ptr)};
            integration::require(ret);

            bsl::print() << "data at spa 0x1000: " << bsl::hex(ptr->data.front()) << bsl::endl;
        }

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