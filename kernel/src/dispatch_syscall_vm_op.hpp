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

#ifndef DISPATCH_SYSCALL_VM_OP_HPP
#define DISPATCH_SYSCALL_VM_OP_HPP

#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <ext_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements the bf_vm_op_create_vm syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page pool to use
    ///   @param mut_vm_pool the VM pool to use
    ///   @param mut_ext_pool the extension pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vm_op_create_vm(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        vm_pool_t &mut_vm_pool,
        ext_pool_t &mut_ext_pool) noexcept -> syscall::bf_status_t
    {
        auto const vmid{mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool)};
        if (bsl::unlikely(!vmid)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = bsl::to_umax_upper_lower(mut_tls.ext_reg0, vmid).get();
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vm_op_destroy_vm syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page pool to use
    ///   @param mut_vm_pool the VM pool to use
    ///   @param vp_pool the VP pool to use
    ///   @param mut_ext_pool the extension pool to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_vm_op_destroy_vm(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        vm_pool_t &mut_vm_pool,
        vp_pool_t const &vp_pool,
        ext_pool_t &mut_ext_pool) noexcept -> syscall::bf_status_t
    {
        auto const ret{mut_vm_pool.deallocate(
            mut_tls, mut_page_pool, vp_pool, mut_ext_pool, bsl::to_u16_unsafe(mut_tls.ext_reg1))};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_vm_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page pool to use
    ///   @param mut_vm_pool the VM pool to use
    ///   @param vp_pool the VM pool to use
    ///   @param mut_ext_pool the extension pool to use
    ///   @param ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_vm_op(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        vm_pool_t &mut_vm_pool,
        vp_pool_t const &vp_pool,
        ext_pool_t &mut_ext_pool,
        ext_t const &ext) noexcept -> syscall::bf_status_t
    {
        if (bsl::unlikely(!ext.is_handle_valid(bsl::to_u64(mut_tls.ext_reg0)))) {
            bsl::error() << "invalid handle "             // --
                         << bsl::hex(mut_tls.ext_reg0)    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
        }

        if (bsl::unlikely(mut_tls.ext != mut_tls.ext_vmexit)) {
            bsl::error() << "vm ops are not allowed by ext "        // --
                         << bsl::hex(ext.id())                      // --
                         << " as it didn't register for vmexits"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

            return syscall::BF_STATUS_INVALID_PERM_DENIED;
        }

        switch (syscall::bf_syscall_index(bsl::to_u64(mut_tls.ext_syscall)).get()) {
            case syscall::BF_VM_OP_CREATE_VM_IDX_VAL.get(): {
                auto const ret{
                    syscall_vm_op_create_vm(mut_tls, mut_page_pool, mut_vm_pool, mut_ext_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VM_OP_DESTROY_VM_IDX_VAL.get(): {
                auto const ret{syscall_vm_op_destroy_vm(
                    mut_tls, mut_page_pool, mut_vm_pool, vp_pool, mut_ext_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            default: {
                break;
            }
        }

        bsl::error() << "unknown syscall "               //--
                     << bsl::hex(mut_tls.ext_syscall)    //--
                     << bsl::endl                        //--
                     << bsl::here();                     //--

        return syscall::BF_STATUS_FAILURE_UNSUPPORTED;
    }
}

#endif
