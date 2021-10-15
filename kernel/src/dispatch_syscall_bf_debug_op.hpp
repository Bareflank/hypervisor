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
#include <bf_types.hpp>
#include <ext_pool_t.hpp>
#include <huge_pool_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vmexit_log_t.hpp>
#include <vp_pool_t.hpp>
#include <vs_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/debug.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
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
                auto const vmid{get_vmid(mut_tls.ext_reg0)};
                if (bsl::unlikely(vmid.is_invalid())) {
                    bsl::print<bsl::V>() << bsl::here();
                    return syscall::BF_STATUS_INVALID_INPUT_REG0;
                }

                vm_pool.dump(mut_tls, vmid);
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_VP_IDX_VAL.get(): {
                auto const vpid{get_vpid(mut_tls.ext_reg0)};
                if (bsl::unlikely(vpid.is_invalid())) {
                    bsl::print<bsl::V>() << bsl::here();
                    return syscall::BF_STATUS_INVALID_INPUT_REG0;
                }

                vp_pool.dump(vpid);
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_VS_IDX_VAL.get(): {
                auto const vsid{get_vsid(mut_tls.ext_reg0)};
                if (bsl::unlikely(vsid.is_invalid())) {
                    bsl::print<bsl::V>() << bsl::here();
                    return syscall::BF_STATUS_INVALID_INPUT_REG0;
                }

                vs_pool.dump(mut_tls, intrinsic, vsid);
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL.get(): {
                auto const ppid{get_ppid(mut_tls, mut_tls.ext_reg0)};
                if (bsl::unlikely(ppid.is_invalid())) {
                    bsl::print<bsl::V>() << bsl::here();
                    return syscall::BF_STATUS_INVALID_INPUT_REG0;
                }

                log.dump(ppid);
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_WRITE_C_IDX_VAL.get(): {
                bsl::print() << static_cast<bsl::char_type>(bsl::to_u8(mut_tls.ext_reg0).get());
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_WRITE_STR_IDX_VAL.get(): {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                auto const *const str{reinterpret_cast<bsl::cstr_type>(mut_tls.ext_reg0)};
                if (bsl::unlikely(nullptr == str)) {
                    return syscall::BF_STATUS_INVALID_INPUT_REG0;
                }

                /// TODO:
                /// - If a bad address is given, it will segfault the kernel.
                ///   This should be fixed to simply segfault the userspace
                ///   application. To do that, we need to detect the page
                ///   fault and return to userspace with the page fault
                ///   information containing the state of the userspace ext
                ///   and not the kernel, as the fault really came from the
                ///   ext and not the kernel.
                ///
                /// - The reason this is not fixed right now is that either
                ///   way, this will lead to something horrible happening,
                ///   and execution will be stopped, so who segfaults is not
                ///   that big of a deal, but for completness, this should
                ///   be fixed in the future.
                ///

                bsl::print() << bsl::string_view{str, bsl::to_umx(mut_tls.ext_reg1)};
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_EXT_IDX_VAL.get(): {
                auto const extid{get_extid(mut_tls.ext_reg0)};
                if (bsl::unlikely(extid.is_invalid())) {
                    bsl::print<bsl::V>() << bsl::here();
                    return syscall::BF_STATUS_INVALID_INPUT_REG0;
                }

                ext_pool.dump(mut_tls, extid);
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
