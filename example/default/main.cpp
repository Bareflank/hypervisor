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

#include <arch_support.hpp>
#include <mk_interface.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// @brief stores the handle the extension will use
    constinit inline syscall::bf_handle_t g_handle{};

    /// <!-- description -->
    ///   @brief Implements the VMExit entry function. This is registered
    ///     by the bootstrap function to execute whenever a VMExit occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param vpsid the ID of the VPS that generated the VMExit
    ///   @param exit_reason the exit reason associated with the VMExit
    ///
    void
    vmexit_entry(bsl::uint16 const vpsid, bsl::uint64 const exit_reason) noexcept
    {
        vmexit(g_handle, vpsid, exit_reason);

        /// NOTE:
        /// - This code is only reached if an error occurs. Executing this
        ///   syscall will tell the microkernel that the VMExit was not
        ///   handled, in which case it will enter a fast fail state.
        ///

        bsl::print<bsl::V>() << bsl::here();
        syscall::bf_control_op_exit();
    }

    /// <!-- description -->
    ///   @brief Implements the fast fail entry function. This is registered
    ///     by the bootstrap function to execute whenever a fast fail occurs.
    ///
    /// <!-- inputs/outputs -->
    ///   @param fail_reason the exit reason associated with the fail
    ///
    void
    fail_entry(syscall::bf_status_t::value_type const fail_reason) noexcept
    {
        bsl::discard(fail_reason);

        /// NOTE:
        /// - Tells the microkernel that we didn't handle the fast fail.
        ///   When this occurs, the microkernel will halt this PP. In most
        ///   cases, there are only two options here:
        ///   - Do the following, and report an error and halt.
        ///   - Return to a parent VPS and continue execution from there,
        ///     which is typically only possible if you are implementing
        ///     more than one VPS/VP per PP (e.g., when implementing guest
        ///     support or VSM support).
        ///
        /// - Another use case is integration testing. We can also use this
        ///   to generate faults that we can recover from to ensure the
        ///   fault system works properly during testing.
        ///

        bsl::print<bsl::V>() << bsl::here();
        syscall::bf_control_op_exit();
    }

    /// <!-- description -->
    ///   @brief Implements the bootstrap entry function. The main function is
    ///     called on PP #0, and is only used to register the bootstrap entry
    ///     function and open a handle. From there, the rest of the bootstrap
    ///     process should occur from the bootstrap function, as this function
    ///     is executed once on each PP, giving you a chance to bootstrap each
    ///     PP as needed.
    ///
    /// <!-- inputs/outputs -->
    ///   @param ppid the physical process to bootstrap
    ///
    void
    bootstrap_entry(bsl::uint16 const ppid) noexcept
    {
        bsl::safe_uint16 vmid{};
        bsl::safe_uint16 vpid{};
        bsl::safe_uint16 vpsid{};
        syscall::bf_status_t status{};

        /// NOTE:
        /// - Before we can create a VM, VP and VPS, we must first register
        ///   for VMExits. If we don't, the microkernel will complain as it
        ///   ensures the extension that registers for VMExits is the only
        ///   extension that can create and manage these resources.
        /// - We also register for fast fail events in case something bad
        ///   happens.
        ///

        status = syscall::bf_callback_op_register_vmexit(g_handle, vmexit_entry);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            syscall::bf_control_op_exit();
        }

        status = syscall::bf_callback_op_register_fail(g_handle, fail_entry);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Create the root VM, root VP and root VPS that we will start.
        ///   Since we are not implementing nested virtualization or VSM
        ///   support, the VP and VPS are always identical.
        ///
        /// IMPORTANT:
        /// - The microkernel does not check to make sure that a VPS is not
        ///   run on different PPs at the same time. This would require an
        ///   enormous amount of overhead on every VMExit to address. As a
        ///   result, it is possible to corrupt the system if you are not
        ///   careful with respect to creating VPSs and running them on the
        ///   proper PPs. You have been warned.
        ///

        if (bsl::ZERO_U16 == ppid) {
            status = syscall::bf_vm_op_create_vm(g_handle, vmid);
            if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
                bsl::print<bsl::V>() << bsl::here();
                syscall::bf_control_op_exit();
            }
        }

        status = syscall::bf_vp_op_create_vp(g_handle, vpid);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            syscall::bf_control_op_exit();
        }

        status = syscall::bf_vps_op_create_vps(g_handle, vpsid);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Initialize the VPS as a root VPS. When the microkernel was
        ///   started, the loader saved the state of the root VP. This
        ///   syscall tells the microkernel to load the VPS with this saved
        ///   state so that when we run the VP, it will contain the state
        ///   just before the microkernel was started.
        ///

        status = syscall::bf_vps_op_init_as_root(g_handle, vpsid);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Initialize architecture specific logic in the VPS.
        ///

        if (bsl::unlikely(!init_vps(g_handle, vpsid))) {
            bsl::print<bsl::V>() << bsl::here();
            syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Run the newly created VP on behalf of the newly created VM
        ///   using the newly created and initialized VPS.
        /// - It should be noted that if bf_vps_op_run succeeds, it will
        ///   not return. Like the rest of the code in this example, we
        ///   return success for unit testing purposes. If this function
        ///   returns, it is actually an error.
        ///

        bsl::discard(syscall::bf_vps_op_run(g_handle, vpsid, vpid, vmid));

        /// NOTE:
        /// - The following is only called if an error occurs. Failure to
        ///   call this function leads to undefined behaviour (likely a
        ///   page fault).
        ///

        bsl::print<bsl::V>() << bsl::here();
        syscall::bf_control_op_exit();
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
    ext_main_entry(bsl::safe_uint32 const &version) noexcept
    {
        syscall::bf_status_t status;

        /// NOTE:
        /// - Check to see if the microkernel speaks the same version as we
        ///   do. Note that this is important. Years from now, the microkernel
        ///   might implement a completely different syscall interface. This
        ///   check ensures that if that happens, this code will not continue
        ///   as it might result in undefined behaviour.
        ///

        if (bsl::unlikely(!syscall::bf_is_spec1_supported(version))) {
            bsl::error() << "unsupported microkernel\n" << bsl::here();
            syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Open a handle with the microkernel which will be used for the
        ///   remaining syscalls.
        ///

        status = syscall::bf_handle_op_open_handle(syscall::BF_SPEC_ID1_VAL, g_handle);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Register the bootstrap entry function so that we can bootstrap
        ///   each PP
        ///

        status = syscall::bf_callback_op_register_bootstrap(g_handle, bootstrap_entry);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            syscall::bf_control_op_exit();
        }

        /// NOTE:
        /// - Wait for callbacks. Note that this function does not return.
        ///   The next time the extension is executed, it will be the
        ///   bootstrap callback that was just previously registered, which
        ///   will be called on each PP that is online. Failure to call this
        ///   function leads to undefined behaviour (likely a page fault).
        ///

        syscall::bf_callback_op_wait();
    }
}
