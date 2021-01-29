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

#ifndef DISPATCH_SYSCALL_CALLBACK_OP_HPP
#define DISPATCH_SYSCALL_CALLBACK_OP_HPP

#include <mk_interface.hpp>
#include <return_to_mk.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/likely.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Implements the bf_callback_op_register_bootstrap syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam EXT_CONCEPT defines the type of ext_t to use
        ///   @param tls the current TLS block
        ///   @param ext the extension that made the syscall
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename EXT_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_callback_op_register_bootstrap(TLS_CONCEPT &tls, EXT_CONCEPT &ext)
            -> syscall::bf_status_t
        {
            if (bsl::unlikely(!ext.is_handle_valid(tls.ext_reg0))) {
                bsl::error() << "invalid handle: "        // --
                             << bsl::hex(tls.ext_reg0)    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
            }

            if (bsl::unlikely(ext.bootstrap_ip())) {
                bsl::error() << "ext ["                                          // --
                             << bsl::hex(ext.id())                               // --
                             << "] already registered a bootstrap callback\n"    // --
                             << bsl::here();                                     // --

                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            ext.set_bootstrap_ip(tls.ext_reg1);
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_callback_op_register_vmexit syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam EXT_CONCEPT defines the type of ext_t to use
        ///   @param tls the current TLS block
        ///   @param ext the extension that made the syscall
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename EXT_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_callback_op_register_vmexit(TLS_CONCEPT &tls, EXT_CONCEPT &ext)
            -> syscall::bf_status_t
        {
            if (bsl::unlikely(!ext.is_handle_valid(tls.ext_reg0))) {
                bsl::error() << "invalid handle: "        // --
                             << bsl::hex(tls.ext_reg0)    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
            }

            if (bsl::likely(nullptr == tls.ext_vmexit)) {
                tls.ext_vmexit = &ext;
            }
            else {
                bsl::error() << "ext ["                                                       // --
                             << bsl::hex(static_cast<EXT_CONCEPT *>(tls.ext_vmexit)->id())    // --
                             << "] already registered a VMExit callback\n"                    // --
                             << bsl::here();                                                  // --

                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            ext.set_vmexit_ip(tls.ext_reg1);
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_callback_op_register_fail syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam EXT_CONCEPT defines the type of ext_t to use
        ///   @param tls the current TLS block
        ///   @param ext the extension that made the syscall
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename EXT_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_callback_op_register_fail(TLS_CONCEPT &tls, EXT_CONCEPT &ext)
            -> syscall::bf_status_t
        {
            if (bsl::unlikely(!ext.is_handle_valid(tls.ext_reg0))) {
                bsl::error() << "invalid handle: "        // --
                             << bsl::hex(tls.ext_reg0)    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
            }

            if (bsl::likely(nullptr == tls.ext_fail)) {
                tls.ext_fail = &ext;
            }
            else {
                bsl::error() << "ext ["                                                     // --
                             << bsl::hex(static_cast<EXT_CONCEPT *>(tls.ext_fail)->id())    // --
                             << "] already registered a fast fail callback\n"               // --
                             << bsl::here();                                                // --

                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            ext.set_fail_ip(tls.ext_reg1);
            return syscall::BF_STATUS_SUCCESS;
        }
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_callback_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam TLS_CONCEPT defines the type of TLS block to use
    ///   @tparam EXT_CONCEPT defines the type of ext_t to use
    ///   @param tls the current TLS block
    ///   @param ext the extension that made the syscall
    ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
    ///     code on failure.
    ///
    template<typename TLS_CONCEPT, typename EXT_CONCEPT>
    [[nodiscard]] constexpr auto
    dispatch_syscall_callback_op(TLS_CONCEPT &tls, EXT_CONCEPT &ext) -> syscall::bf_status_t
    {
        syscall::bf_status_t ret{};

        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_CALLBACK_OP_WAIT_IDX_VAL.get(): {
                return_to_mk(bsl::ZERO_UMAX.get());
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_CALLBACK_OP_REGISTER_BOOTSTRAP_IDX_VAL.get(): {
                ret = details::syscall_callback_op_register_bootstrap(tls, ext);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_CALLBACK_OP_REGISTER_VMEXIT_IDX_VAL.get(): {
                ret = details::syscall_callback_op_register_vmexit(tls, ext);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_CALLBACK_OP_REGISTER_FAIL_IDX_VAL.get(): {
                ret = details::syscall_callback_op_register_fail(tls, ext);
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
