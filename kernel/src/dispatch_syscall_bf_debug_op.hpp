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

#ifndef DISPATCH_SYSCALL_BF_DEBUG_OP_HPP
#define DISPATCH_SYSCALL_BF_DEBUG_OP_HPP

#include "dispatch_syscall_helpers.hpp"

#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vmexit_log_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

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
    ///   @param mut_tls the current TLS block
    ///   @param page_pool the page_pool_t to use
    ///   @param huge_pool the huge pool to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param vs_pool the vs_pool_t to use
    ///   @param ext_pool the ext_pool_t to use
    ///   @param log the VMExit log to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_bf_debug_op(
        tls_t &mut_tls,
        page_pool_t const &page_pool,
        huge_pool_t const &huge_pool,
        intrinsic_t const &intrinsic,
        vm_pool_t const &vm_pool,
        vp_pool_t const &vp_pool,
        vs_pool_t const &vs_pool,
        ext_pool_t const &ext_pool,
        vmexit_log_t const &log) noexcept -> syscall::bf_status_t
    {
        switch (syscall::bf_syscall_index(mut_tls.ext_syscall).get()) {
            case syscall::BF_DEBUG_OP_OUT_IDX_VAL.get(): {
                bsl::print() << bsl::hex(mut_tls.ext_reg0)    //--
                             << " "                           //--
                             << bsl::hex(mut_tls.ext_reg1)    //--
                             << bsl::endl;                    //--
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_VM_IDX_VAL.get(): {
                vm_pool.dump(mut_tls, get_vmid(mut_tls.ext_reg0));
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_VP_IDX_VAL.get(): {
                vp_pool.dump(get_vpid(mut_tls.ext_reg0));
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_VS_IDX_VAL.get(): {
                vs_pool.dump(mut_tls, intrinsic, get_vsid(mut_tls.ext_reg0));
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL.get(): {
                log.dump(get_ppid(mut_tls, mut_tls.ext_reg0));
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_WRITE_C_IDX_VAL.get(): {
                bsl::print() << static_cast<bsl::char_type>(bsl::to_u8(mut_tls.ext_reg0).get());
                return syscall::BF_STATUS_SUCCESS;
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

                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                bsl::print() << reinterpret_cast<bsl::cstr_type>(mut_tls.ext_reg0);
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_EXT_IDX_VAL.get(): {
                ext_pool.dump(mut_tls, get_extid(mut_tls.ext_reg0));
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_PAGE_POOL_IDX_VAL.get(): {
                page_pool.dump(mut_tls);
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_HUGE_POOL_IDX_VAL.get(): {
                huge_pool.dump(mut_tls);
                return syscall::BF_STATUS_SUCCESS;
            }

            default: {
                break;
            }
        }

        return report_syscall_unknown_unsupported(mut_tls);
    }
}

#endif
