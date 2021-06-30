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

#ifndef DISPATCH_SYSCALL_INTRINSIC_OP_HPP
#define DISPATCH_SYSCALL_INTRINSIC_OP_HPP

#include <bf_constants.hpp>
#include <ext_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements the bf_intrinsic_op_rdmsr syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param intrinsic the intrinsics to use
    ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
    ///     code on failure.
    ///
    [[nodiscard]] constexpr auto
    syscall_intrinsic_op_rdmsr(tls_t &tls, intrinsic_t &intrinsic) -> bsl::errc_type
    {
        /// TODO:
        /// - Move this logic to the dispatch_syscall_entry.S and implement
        ///   this right in ASM. This way, we can do the smallest amount of
        ///   state save logic and execute this instruction as fast as
        ///   possible. Just make sure that the safe version is used, and
        ///   it will still need to make sure that the extension is not
        ///   trying to read/write MSRs that the microkernel is using.
        ///

        auto const val{intrinsic.rdmsr(bsl::to_u32_unsafe(tls.ext_reg1))};
        if (bsl::unlikely(!val)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        tls.ext_reg0 = val.get();

        tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_intrinsic_op_wrmsr syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param intrinsic the intrinsics to use
    ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
    ///     code on failure.
    ///
    [[nodiscard]] constexpr auto
    syscall_intrinsic_op_wrmsr(tls_t &tls, intrinsic_t &intrinsic) -> bsl::errc_type
    {
        /// TODO:
        /// - Move this logic to the dispatch_syscall_entry.S and implement
        ///   this right in ASM. This way, we can do the smallest amount of
        ///   state save logic and execute this instruction as fast as
        ///   possible. Just make sure that the safe version is used, and
        ///   it will still need to make sure that the extension is not
        ///   trying to read/write MSRs that the microkernel is using.
        ///

        auto const ret{intrinsic.wrmsr(bsl::to_u32_unsafe(tls.ext_reg1), tls.ext_reg2)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_intrinsic_op_invlpga syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param intrinsic the intrinsics to use
    ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
    ///     code on failure.
    ///
    [[nodiscard]] constexpr auto
    syscall_intrinsic_op_invlpga(tls_t &tls, intrinsic_t &intrinsic) -> bsl::errc_type
    {
        auto const ret{intrinsic.invlpga(tls.ext_reg1, tls.ext_reg2)};
        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return ret;
        }

        tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_intrinsic_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param tls the current TLS block
    ///   @param intrinsic the intrinsics to use
    ///   @param ext the extension that made the syscall
    ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
    ///     code on failure.
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_intrinsic_op(tls_t &tls, intrinsic_t &intrinsic, ext_t &ext) -> bsl::errc_type
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
            case syscall::BF_INTRINSIC_OP_RDMSR_IDX_VAL.get(): {
                ret = syscall_intrinsic_op_rdmsr(tls, intrinsic);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_INTRINSIC_OP_WRMSR_IDX_VAL.get(): {
                ret = syscall_intrinsic_op_wrmsr(tls, intrinsic);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_INTRINSIC_OP_INVLPGA_IDX_VAL.get(): {
                ret = syscall_intrinsic_op_invlpga(tls, intrinsic);
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
