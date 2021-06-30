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

#ifndef DISPATCH_SYSCALL_DEBUG_OP_HPP
#define DISPATCH_SYSCALL_DEBUG_OP_HPP

#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vmexit_log_t.hpp>
#include <vp_pool_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/char_type.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/debug.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Dispatches the bf_debug_op syscalls
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
    ///   @param log the VMExit log to use
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     otherwise
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_debug_op(
        tls_t &tls,
        page_pool_t &page_pool,
        huge_pool_t &huge_pool,
        intrinsic_t &intrinsic,
        vm_pool_t &vm_pool,
        vp_pool_t &vp_pool,
        vps_pool_t &vps_pool,
        ext_pool_t &ext_pool,
        vmexit_log_t &log) noexcept -> bsl::errc_type
    {
        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_DEBUG_OP_OUT_IDX_VAL.get(): {
                bsl::print() << bsl::hex(tls.ext_reg0)    //--
                             << " "                       //--
                             << bsl::hex(tls.ext_reg1)    //--
                             << bsl::endl;                //--

                tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
                return bsl::errc_success;
            }

            case syscall::BF_DEBUG_OP_DUMP_VM_IDX_VAL.get(): {
                vm_pool.dump(tls, bsl::to_u16_unsafe(tls.ext_reg0));

                tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
                return bsl::errc_success;
            }

            case syscall::BF_DEBUG_OP_DUMP_VP_IDX_VAL.get(): {
                vp_pool.dump(tls, bsl::to_u16_unsafe(tls.ext_reg0));

                tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
                return bsl::errc_success;
            }

            case syscall::BF_DEBUG_OP_DUMP_VPS_IDX_VAL.get(): {
                vps_pool.dump(tls, intrinsic, bsl::to_u16_unsafe(tls.ext_reg0));

                tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
                return bsl::errc_success;
            }

            case syscall::BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL.get(): {
                log.dump(bsl::to_u16_unsafe(tls.ext_reg0));

                tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
                return bsl::errc_success;
            }

            case syscall::BF_DEBUG_OP_WRITE_C_IDX_VAL.get(): {
                bsl::print() << static_cast<bsl::char_type>(bsl::to_u8(tls.ext_reg0).get());

                tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
                return bsl::errc_success;
            }

            case syscall::BF_DEBUG_OP_WRITE_STR_IDX_VAL.get(): {

                /// NOTE:
                /// - This is the only syscall that might produce an
                ///   exception, and that is due to the need to access user
                ///   space memory. If this occurs, reversal is not needed.
                /// - The function is still marked as exception unsafe, but
                ///   in reality, if an exception fires, there is nothing to
                ///   do, and likely will just result in corrupt debugging
                ///   information.
                ///

                bsl::print() << bsl::to_ptr<bsl::cstr_type>(tls.ext_reg0);

                tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
                return bsl::errc_success;
            }

            case syscall::BF_DEBUG_OP_DUMP_EXT_IDX_VAL.get(): {
                ext_pool.dump(tls, page_pool, bsl::to_u16_unsafe(tls.ext_reg0));

                tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
                return bsl::errc_success;
            }

            case syscall::BF_DEBUG_OP_DUMP_PAGE_POOL_IDX_VAL.get(): {
                page_pool.dump();

                tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
                return bsl::errc_success;
            }

            case syscall::BF_DEBUG_OP_DUMP_HUGE_POOL_IDX_VAL.get(): {
                huge_pool.dump();

                tls.syscall_ret_status = syscall::BF_STATUS_SUCCESS.get();
                return bsl::errc_success;
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
