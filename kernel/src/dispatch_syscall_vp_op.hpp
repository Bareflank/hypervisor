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

#ifndef DISPATCH_SYSCALL_VP_OP_HPP
#define DISPATCH_SYSCALL_VP_OP_HPP

#include <mk_interface.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Implements the bf_vp_op_create_vp syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VP_POOL_CONCEPT defines the type of VP pool to use
        ///   @param tls the current TLS block
        ///   @param vp_pool the VP pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VP_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vp_op_create_vp(TLS_CONCEPT &tls, VP_POOL_CONCEPT &vp_pool) -> syscall::bf_status_t
        {
            auto const vpid{vp_pool.allocate()};
            if (bsl::unlikely(!vpid)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            tls.ext_reg0 = bsl::to_umax(vpid).get();
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_vp_op_destroy_vp syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VP_POOL_CONCEPT defines the type of VP pool to use
        ///   @param tls the current TLS block
        ///   @param vp_pool the VP pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VP_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_vp_op_destroy_vp(TLS_CONCEPT &tls, VP_POOL_CONCEPT &vp_pool) -> syscall::bf_status_t
        {
            if (bsl::unlikely(!vp_pool.deallocate(bsl::to_u16_unsafe(tls.ext_reg1)))) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return syscall::BF_STATUS_SUCCESS;
        }
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_vp_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam TLS_CONCEPT defines the type of TLS block to use
    ///   @tparam EXT_CONCEPT defines the type of ext_t to use
    ///   @tparam VP_POOL_CONCEPT defines the type of VP pool to use
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @param vp_pool the VP pool to use
    ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
    ///     code on failure.
    ///
    template<typename TLS_CONCEPT, typename EXT_CONCEPT, typename VP_POOL_CONCEPT>
    [[nodiscard]] constexpr auto
    dispatch_syscall_vp_op(TLS_CONCEPT &tls, EXT_CONCEPT const &ext, VP_POOL_CONCEPT &vp_pool)
        -> syscall::bf_status_t
    {
        syscall::bf_status_t ret{};

        if (bsl::unlikely(!ext.is_handle_valid(tls.ext_reg0))) {
            bsl::error() << "invalid handle: "        // --
                         << bsl::hex(tls.ext_reg0)    // --
                         << bsl::endl                 // --
                         << bsl::here();              // --

            return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
        }

        if (bsl::unlikely(tls.ext != tls.ext_vmexit)) {
            bsl::error() << "vp_ops not allowed by ext "            // --
                         << bsl::hex(ext.id())                      // --
                         << " as it didn't register for vmexits"    // --
                         << bsl::endl                               // --
                         << bsl::here();                            // --

            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_VP_OP_CREATE_VP_IDX_VAL.get(): {
                ret = details::syscall_vp_op_create_vp(tls, vp_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VP_OP_DESTROY_VP_IDX_VAL.get(): {
                ret = details::syscall_vp_op_destroy_vp(tls, vp_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            default: {
                bsl::error() << "unknown syscall index: "    //--
                             << bsl::hex(tls.ext_syscall)    //--
                             << bsl::endl                    //--
                             << bsl::here();                 //--

                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }
        }
    }
}

#endif
