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
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page pool to use
    ///   @param mut_ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_mem_op_alloc_page(tls_t &mut_tls, page_pool_t &mut_page_pool, ext_t &mut_ext) noexcept
        -> syscall::bf_status_t
    {
        auto const page{mut_ext.alloc_page(mut_tls, mut_page_pool)};
        if (bsl::unlikely(!page.virt)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = page.virt.get();
        mut_tls.ext_reg1 = page.phys.get();

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_mem_op_free_page syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_mem_op_free_page(tls_t &mut_tls, ext_t &mut_ext) noexcept -> syscall::bf_status_t
    {
        auto const ret{mut_ext.free_page(bsl::to_umax(mut_tls.ext_reg1))};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_mem_op_alloc_huge syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page pool to use
    ///   @param mut_huge_pool the huge pool to use
    ///   @param mut_ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_mem_op_alloc_huge(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        huge_pool_t &mut_huge_pool,
        ext_t &mut_ext) noexcept -> syscall::bf_status_t
    {
        auto const huge{mut_ext.alloc_huge(
            mut_tls, mut_page_pool, mut_huge_pool, bsl::to_umax(mut_tls.ext_reg1))};
        if (bsl::unlikely(!huge.virt)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = huge.virt.get();
        mut_tls.ext_reg1 = huge.phys.get();

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_mem_op_free_huge syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_mem_op_free_huge(tls_t &mut_tls, ext_t &mut_ext) noexcept -> syscall::bf_status_t
    {
        auto const ret{mut_ext.free_huge(bsl::to_umax(mut_tls.ext_reg1))};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_mem_op_alloc_heap syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page pool to use
    ///   @param mut_ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_mem_op_alloc_heap(tls_t &mut_tls, page_pool_t &mut_page_pool, ext_t &mut_ext) noexcept
        -> syscall::bf_status_t
    {
        auto const old_heap_virt{
            mut_ext.alloc_heap(mut_tls, mut_page_pool, bsl::to_umax(mut_tls.ext_reg1))};
        if (bsl::unlikely(!old_heap_virt)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = old_heap_virt.get();
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_mem_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page pool to use
    ///   @param mut_huge_pool the huge pool to use
    ///   @param mut_ext the extension that made the syscall
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_mem_op(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        huge_pool_t &mut_huge_pool,
        ext_t &mut_ext) noexcept -> syscall::bf_status_t
    {
        if (bsl::unlikely(!mut_ext.is_handle_valid(bsl::to_u64(mut_tls.ext_reg0)))) {
            bsl::error() << "invalid handle "             // --
                         << bsl::hex(mut_tls.ext_reg0)    // --
                         << bsl::endl                     // --
                         << bsl::here();                  // --

            return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
        }

        switch (syscall::bf_syscall_index(bsl::to_u64(mut_tls.ext_syscall)).get()) {
            case syscall::BF_MEM_OP_ALLOC_PAGE_IDX_VAL.get(): {
                auto const ret{syscall_mem_op_alloc_page(mut_tls, mut_page_pool, mut_ext)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_MEM_OP_FREE_PAGE_IDX_VAL.get(): {
                auto const ret{syscall_mem_op_free_page(mut_tls, mut_ext)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_MEM_OP_ALLOC_HUGE_IDX_VAL.get(): {
                auto const ret{
                    syscall_mem_op_alloc_huge(mut_tls, mut_page_pool, mut_huge_pool, mut_ext)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_MEM_OP_FREE_HUGE_IDX_VAL.get(): {
                auto const ret{syscall_mem_op_free_huge(mut_tls, mut_ext)};
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_MEM_OP_ALLOC_HEAP_IDX_VAL.get(): {
                auto const ret{syscall_mem_op_alloc_heap(mut_tls, mut_page_pool, mut_ext)};
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

        bsl::error() << "unknown syscall index "         //--
                     << bsl::hex(mut_tls.ext_syscall)    //--
                     << bsl::endl                        //--
                     << bsl::here();                     //--

        return syscall::BF_STATUS_FAILURE_UNSUPPORTED;
    }
}

#endif
