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

#ifndef DISPATCH_SYSCALL_HANDLE_OP_HPP
#define DISPATCH_SYSCALL_HANDLE_OP_HPP

#include <mk_interface.hpp>

#include <bsl/debug.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Implements the bf_handle_op_open_handle syscall
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
        syscall_handle_op_open_handle(TLS_CONCEPT &tls, EXT_CONCEPT &ext) -> syscall::bf_status_t
        {
            if (bsl::unlikely(bsl::to_u32(tls.ext_reg0) != syscall::BF_SPEC_ID1_VAL)) {
                bsl::error() << "unsupported syscall interface: "    //--
                             << bsl::hex(tls.ext_reg0)               //--
                             << bsl::endl                            //--
                             << bsl::here();                         //--

                return syscall::BF_STATUS_FAILURE_UNSUPPORTED;
            }

            auto const handle{ext.open_handle()};
            if (bsl::unlikely(!handle)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            tls.ext_reg0 = handle.get();
            return syscall::BF_STATUS_SUCCESS;
        }

        /// <!-- description -->
        ///   @brief Implements the bf_handle_op_close_handle syscall
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
        syscall_handle_op_close_handle(TLS_CONCEPT &tls, EXT_CONCEPT &ext) -> syscall::bf_status_t
        {
            if (bsl::unlikely(!ext.is_handle_valid(tls.ext_reg0))) {
                bsl::error() << "invalid handle: "        // --
                             << bsl::hex(tls.ext_reg0)    // --
                             << bsl::endl                 // --
                             << bsl::here();              // --

                return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
            }

            ext.close_handle();
            return syscall::BF_STATUS_SUCCESS;
        }
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_handle_op syscalls
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
    dispatch_syscall_handle_op(TLS_CONCEPT &tls, EXT_CONCEPT &ext) -> syscall::bf_status_t
    {
        syscall::bf_status_t ret{};

        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_HANDLE_OP_OPEN_HANDLE_IDX_VAL.get(): {
                ret = details::syscall_handle_op_open_handle(tls, ext);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_HANDLE_OP_CLOSE_HANDLE_IDX_VAL.get(): {
                ret = details::syscall_handle_op_close_handle(tls, ext);
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
