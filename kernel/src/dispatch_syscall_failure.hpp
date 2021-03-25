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

#ifndef DISPATCH_SYSCALL_FAILURE_HPP
#define DISPATCH_SYSCALL_FAILURE_HPP

#include <dispatch_syscall_callback_op_failure.hpp>
#include <dispatch_syscall_control_op_failure.hpp>
#include <dispatch_syscall_debug_op_failure.hpp>
#include <dispatch_syscall_handle_op_failure.hpp>
// #include <dispatch_syscall_intrinsic_op_failure.hpp>
// #include <dispatch_syscall_mem_op_failure.hpp>
#include <bf_constants.hpp>
#include <dispatch_syscall_vm_op_failure.hpp>
#include <dispatch_syscall_vp_op_failure.hpp>
#include <dispatch_syscall_vps_op_failure.hpp>
#include <ext_pool_t.hpp>
#include <ext_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides the main entry point for all syscalls failures.
    ///     If something goes wrong, this is the code that will undo any
    ///     state changes that might have occurred.
    ///     - If an error should occur (the syscall handler returns an
    ///       error code), we need to undo any state changes that might
    ///       have occurred.
    ///     - We cannot undo the state changes in the handler itself. This
    ///       is because if an exception were to fire, those state changes
    ///       would not be reversed. For example, you could put some logic
    ///       in the syscall handler that detects an error and reverses the
    ///       change that it previously made. But what if an exception fires
    ///       after the change, but before the reversal code executes.
    ///     - The point of these failure functions is to handle all state
    ///       reversal changes here. If an exception fires, or if an error
    ///       occurs, the reversal logic happens in the same place so that
    ///       it can be handled.
    ///     - These reversal functions need to be able to handle the case
    ///       were an exception fires while a lock was taken. Not only does
    ///       it need to reverse the state, but it also needs to clean up
    ///       the lock state so that this code can handle the reversal
    ///       without deadlock, and so that future syscalls do not also lead
    ///       to potential deadlock.
    ///     - Not every function is likely to cause an exception. With decent
    ///       unit testing, a fair number of syscalls will never produce an
    ///       exception because they are not doing anything outside of state
    ///       management. In either case, we handle any state reversal here
    ///       just in case.
    ///     - Not all types of exceptions can be handled. There are some that
    ///       if they occur, really bad things would happen and there just is
    ///       no reasonable way to record. For example, if CR3 is swapped and
    ///       the microkernel can no longer execute, there is nothing we can
    ///       do. These types of errors however are easy to detect with system
    ///       and integration testing, so they are less of a potential issue.
    ///       What we are trying to provide is some protection against coding
    ///       mistakes as things are being worked on that would lead to hard
    ///       to debug situations. In otherwords, try to provide some fault
    ///       tolerance so that the system is easier to work with in general.
    ///     - It is possible that this code could fire an exception. If that
    ///       happens, something is really bad and there is nothing we can
    ///       do but fast fail again and leave.
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param page_pool the page pool to use
    ///   @param huge_pool the huge pool to use
    ///   @param intrinsic the intrinsics to use
    ///   @param vm_pool the VM pool to use
    ///   @param vp_pool the VP pool to use
    ///   @param vps_pool the VPS pool to use
    ///   @param ext_pool the extension pool to use
    ///   @param ext the extension that made the syscall
    ///   @param log the VMExit log to use
    ///   @return Returns bsl::exit_success on success, bsl::exit_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_failure(
        tls_t &tls,
        page_pool_t &page_pool,
        huge_pool_t &huge_pool,
        intrinsic_t &intrinsic,
        vm_pool_t &vm_pool,
        vp_pool_t &vp_pool,
        vps_pool_t &vps_pool,
        ext_pool_t &ext_pool,
        ext_t &ext,
        vmexit_log_t &log) noexcept -> bsl::exit_code
    {
        bsl::discard(huge_pool);
        bsl::discard(log);

        bsl::errc_type ret{bsl::errc_success};

        switch (syscall::bf_syscall_opcode(tls.ext_syscall).get()) {
            case syscall::BF_CONTROL_OP_VAL.get(): {
                dispatch_syscall_control_op_failure(tls);
                break;
            }

            case syscall::BF_HANDLE_OP_VAL.get(): {
                ret = dispatch_syscall_handle_op_failure(tls, ext);
                break;
            }

            case syscall::BF_DEBUG_OP_VAL.get(): {
                dispatch_syscall_debug_op_failure(tls);
                break;
            }

            case syscall::BF_CALLBACK_OP_VAL.get(): {
                dispatch_syscall_callback_op_failure(tls, ext);
                break;
            }

            case syscall::BF_VM_OP_VAL.get(): {
                ret = dispatch_syscall_vm_op_failure(tls, page_pool, vm_pool, vp_pool, ext_pool);
                break;
            }

            case syscall::BF_VP_OP_VAL.get(): {
                ret = dispatch_syscall_vp_op_failure(tls, vp_pool, vps_pool);
                break;
            }

            case syscall::BF_VPS_OP_VAL.get(): {
                ret = dispatch_syscall_vps_op_failure(
                    tls, page_pool, intrinsic, vm_pool, vp_pool, vps_pool, ext);
                break;
            }

                //     case syscall::BF_INTRINSIC_OP_VAL.get(): {
                //         ret = dispatch_syscall_intrinsic_op(tls, ext, intrinsic);
                //         if (bsl::unlikely(!ret)) {
                //             bsl::print<bsl::V>() << bsl::here();
                //             return bsl::exit_failure;
                //         }

                //         return bsl::exit_success;
                //     }

                //     case syscall::BF_MEM_OP_VAL.get(): {
                //         ret = dispatch_syscall_mem_op(tls, ext);
                //         if (bsl::unlikely(!ret)) {
                //             bsl::print<bsl::V>() << bsl::here();
                //             return bsl::exit_failure;
                //         }

                //         return bsl::exit_success;
                //     }

            default: {
                break;
            }
        }

        if (!ret) {
            bsl::print() << bsl::red << "  --> FAILED TO REVERSE STATE. CORRUPTION LIKELY";    //--
            bsl::print() << bsl::rst << bsl::endl;

            return bsl::exit_failure;
        }

        return bsl::exit_success;
    }
}

#endif
