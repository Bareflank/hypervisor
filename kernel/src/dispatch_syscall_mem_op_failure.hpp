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

#ifndef DISPATCH_SYSCALL_MEM_OP_HPP
#define DISPATCH_SYSCALL_MEM_OP_HPP

#include <bf_constants.hpp>
#include <ext_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements the bf_mem_op_alloc_page syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    syscall_mem_op_alloc_page(tls_t &tls, ext_t &ext) noexcept -> bsl::errc_type
    {
        /// NOTE:
        /// - ext.alloc_page is assumped to be exception UNSAFE
        ///

        auto const page{ext.alloc_page(tls)};
        if (bsl::unlikely(!page.virt)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - The remaining is assumped to be exception safe
        ///

        tls.ext_reg0 = page.virt.get();
        tls.ext_reg1 = page.phys.get();

        tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_mem_op_free_page syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    syscall_mem_op_free_page(tls_t &tls, ext_t &ext) noexcept -> bsl::errc_type
    {
        auto const ret{ext.free_page(bsl::to_umax(tls.ext_reg1))};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_mem_op_alloc_huge syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    syscall_mem_op_alloc_huge(tls_t &tls, ext_t &ext) noexcept -> bsl::errc_type
    {
        auto const huge{ext.alloc_huge(tls, bsl::to_umax(tls.ext_reg1))};
        if (bsl::unlikely(!huge.virt)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        tls.ext_reg0 = huge.virt.get();
        tls.ext_reg1 = huge.phys.get();

        tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_mem_op_free_huge syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    syscall_mem_op_free_huge(tls_t &tls, ext_t &ext) noexcept -> bsl::errc_type
    {
        auto const ret{ext.free_huge(bsl::to_umax(tls.ext_reg1))};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_mem_op_alloc_heap syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    syscall_mem_op_alloc_heap(tls_t &tls, ext_t &ext) noexcept -> bsl::errc_type
    {
        auto const previous_heap_virt{ext.alloc_heap(tls, bsl::to_umax(tls.ext_reg1))};
        if (bsl::unlikely(!previous_heap_virt)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        tls.ext_reg0 = previous_heap_virt.get();

        tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_mem_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_mem_op(tls_t &tls, ext_t &ext) noexcept -> bsl::errc_type
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

        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_MEM_OP_ALLOC_PAGE_IDX_VAL.get(): {
                ret = syscall_mem_op_alloc_page(tls, ext);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_MEM_OP_FREE_PAGE_IDX_VAL.get(): {
                ret = syscall_mem_op_free_page(tls, ext);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_MEM_OP_ALLOC_HUGE_IDX_VAL.get(): {
                ret = syscall_mem_op_alloc_huge(tls, ext);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_MEM_OP_FREE_HUGE_IDX_VAL.get(): {
                ret = syscall_mem_op_free_huge(tls, ext);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_MEM_OP_ALLOC_HEAP_IDX_VAL.get(): {
                ret = syscall_mem_op_alloc_heap(tls, ext);
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
