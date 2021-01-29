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

#include <mk_interface.hpp>

#include <bsl/char_type.hpp>
#include <bsl/cstr_type.hpp>
#include <bsl/debug.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Implements the debug_op_dump_vps syscall
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
        ///   @param tls the current TLS block
        ///   @param vps_pool the VPS pool to use
        ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
        ///     code on failure.
        ///
        template<typename TLS_CONCEPT, typename VPS_POOL_CONCEPT>
        [[nodiscard]] constexpr auto
        syscall_debug_op_dump_vps(TLS_CONCEPT &tls, VPS_POOL_CONCEPT &vps_pool)
            -> syscall::bf_status_t
        {
            auto const ret{vps_pool.dump(tls, bsl::to_u16_unsafe(tls.ext_reg0))};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNKNOWN;
            }

            return syscall::BF_STATUS_SUCCESS;
        }
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_debug_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam SMAP_GUARD_CONCEPT defines the type of smap guard to use
    ///   @tparam TLS_CONCEPT defines the type of TLS block to use
    ///   @tparam VM_POOL_CONCEPT defines the type of VM pool to use
    ///   @tparam VP_POOL_CONCEPT defines the type of VP pool to use
    ///   @tparam VPS_POOL_CONCEPT defines the type of VPS pool to use
    ///   @param tls the current TLS block
    ///   @param vm_pool the VM pool to use
    ///   @param vp_pool the VP pool to use
    ///   @param vps_pool the VPS pool to use
    ///   @return Returns syscall::BF_STATUS_SUCCESS on success or an error
    ///     code on failure.
    ///
    template<
        typename SMAP_GUARD_CONCEPT,
        typename TLS_CONCEPT,
        typename VM_POOL_CONCEPT,
        typename VP_POOL_CONCEPT,
        typename VPS_POOL_CONCEPT>
    [[nodiscard]] constexpr auto
    dispatch_syscall_debug_op(
        TLS_CONCEPT &tls,
        VM_POOL_CONCEPT &vm_pool,
        VP_POOL_CONCEPT &vp_pool,
        VPS_POOL_CONCEPT &vps_pool) noexcept -> syscall::bf_status_t
    {
        syscall::bf_status_t ret{};

        switch (syscall::bf_syscall_index(tls.ext_syscall).get()) {
            case syscall::BF_DEBUG_OP_OUT_IDX_VAL.get(): {
                bsl::print() << bsl::hex(tls.ext_reg0)    //--
                             << " "                       //--
                             << bsl::hex(tls.ext_reg1)    //--
                             << bsl::endl;                //--

                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_DUMP_VM_IDX_VAL.get(): {
                bsl::discard(vm_pool);
                bsl::error() << "bf_debug_op_dump_vms unsupported\n" << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNSUPPORTED;
            }

            case syscall::BF_DEBUG_OP_DUMP_VP_IDX_VAL.get(): {
                bsl::discard(vp_pool);
                bsl::error() << "bf_debug_op_dump_vps unsupported\n" << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNSUPPORTED;
            }

            case syscall::BF_DEBUG_OP_DUMP_VPS_IDX_VAL.get(): {
                ret = details::syscall_debug_op_dump_vps(tls, vps_pool);
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_DEBUG_OP_DUMP_VMEXIT_LOG_IDX_VAL.get(): {
                bsl::error() << "bf_debug_op_dump_vmexit_log unsupported\n" << bsl::here();
                return syscall::BF_STATUS_FAILURE_UNSUPPORTED;
            }

            case syscall::BF_DEBUG_OP_WRITE_C_IDX_VAL.get(): {
                bsl::print() << static_cast<bsl::char_type>(bsl::to_u8(tls.ext_reg0).get());
                return syscall::BF_STATUS_SUCCESS;
            }

            case syscall::BF_DEBUG_OP_WRITE_STR_IDX_VAL.get(): {
                SMAP_GUARD_CONCEPT unlock{};
                bsl::print() << bsl::to_ptr<bsl::cstr_type>(tls.ext_reg0);
                return syscall::BF_STATUS_SUCCESS;
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
