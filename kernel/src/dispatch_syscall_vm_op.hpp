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
    ///   @param tls the current TLS block
    ///   @param page_pool the page pool to use
    ///   @param vm_pool the VM pool to use
    ///   @param ext_pool the extension pool to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    syscall_vm_op_create_vm(
        tls_t &tls, page_pool_t &page_pool, vm_pool_t &vm_pool, ext_pool_t &ext_pool) noexcept
        -> bsl::errc_type
    {
        auto const vmid{vm_pool.allocate(tls, page_pool, ext_pool)};
        if (bsl::unlikely(!vmid)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        constexpr auto mask{0xFFFFFFFFFFFF0000_umax};
        tls.ext_reg0 = ((tls.ext_reg0 & mask) | bsl::to_umax(vmid)).get();

        tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vm_op_destroy_vm syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param page_pool the page pool to use
    ///   @param vm_pool the VM pool to use
    ///   @param vp_pool the VP pool to use
    ///   @param ext_pool the extension pool to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    syscall_vm_op_destroy_vm(
        tls_t &tls,
        page_pool_t &page_pool,
        vm_pool_t &vm_pool,
        vp_pool_t &vp_pool,
        ext_pool_t &ext_pool) noexcept -> bsl::errc_type
    {
        auto const vmid{bsl::to_u16_unsafe(tls.ext_reg1)};
        auto const ret{vm_pool.deallocate(tls, page_pool, vp_pool, ext_pool, vmid)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_vm_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param page_pool the page pool to use
    ///   @param vm_pool the VM pool to use
    ///   @param vp_pool the VM pool to use
    ///   @param ext_pool the extension pool to use
    ///   @param ext the extension that made the syscall
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_vm_op(
        tls_t &tls,
        page_pool_t &page_pool,
        vm_pool_t &vm_pool,
        vp_pool_t &vp_pool,
        ext_pool_t &ext_pool,
        ext_t &ext) -> bsl::errc_type
    {
        bsl::errc_type ret{};

        if (bsl::unlikely(!ext.is_handle_valid(tls.ext_reg0))) {
            bsl::error() << "invalid handle "         // --
                         << bsl::hex(tls.ext_reg0)    // --
                         << bsl::endl                 // --
                         << bsl::here();              // --

            tls.syscall_ret_status = syscall::BF_STATUS_FAILURE_INVALID_HANDLE.get();
            return bsl::errc_failure;
        }

        if (bsl::unlikely(tls.ext != tls.ext_vmexit)) {
            bsl::error() << "vm ops are not allowed by ext "        // --
                         << bsl::hex(ext.id())                      // --
                         << " as it didn't register for vmexits"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

            tls.syscall_ret_status = syscall::BF_STATUS_INVALID_PERM_EXT.get();
            return bsl::errc_failure;
        }

        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_VM_OP_CREATE_VM_IDX_VAL.get(): {
                ret = syscall_vm_op_create_vm(tls, page_pool, vm_pool, ext_pool);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VM_OP_DESTROY_VM_IDX_VAL.get(): {
                ret = syscall_vm_op_destroy_vm(tls, page_pool, vm_pool, vp_pool, ext_pool);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            default: {
                break;
            }
        }

        bsl::error() << "unknown syscall index "     //--
                     << bsl::hex(tls.ext_syscall)    //--
                     << bsl::endl                    //--
                     << bsl::here();                 //--

        tls.syscall_ret_status = syscall::BF_STATUS_FAILURE_UNSUPPORTED.get();
        return bsl::errc_failure;
    }
}

#endif
