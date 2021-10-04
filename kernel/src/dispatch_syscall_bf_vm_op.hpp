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

#ifndef DISPATCH_SYSCALL_BF_VM_OP_HPP
#define DISPATCH_SYSCALL_BF_VM_OP_HPP

#include <bf_constants.hpp>
#include <ext_pool_t.hpp>
#include <ext_t.hpp>
#include <tls_t.hpp>
#include <vm_pool_t.hpp>
#include <vp_pool_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/finally.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements the bf_vm_op_create_vm syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param mut_ext_pool the ext_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_bf_vm_op_create_vm(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        vm_pool_t &mut_vm_pool,
        ext_pool_t &mut_ext_pool) noexcept -> syscall::bf_status_t
    {
        auto const vmid{mut_vm_pool.allocate(mut_tls, mut_page_pool, mut_ext_pool)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = bsl::merge_umx_with_u16(mut_tls.ext_reg0, vmid).get();
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vm_op_destroy_vm syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param mut_ext_pool the ext_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_bf_vm_op_destroy_vm(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        vm_pool_t &mut_vm_pool,
        vp_pool_t const &vp_pool,
        ext_pool_t &mut_ext_pool) noexcept -> syscall::bf_status_t
    {
        auto const vmid{get_allocated_vmid(mut_tls.ext_reg1, mut_vm_pool)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        bool const vm_destroyable{is_vm_destroyable(mut_tls, mut_vm_pool, vp_pool, vmid)};
        if (bsl::unlikely(!vm_destroyable)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_vm_pool.deallocate(mut_tls, mut_page_pool, mut_ext_pool, vmid);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vm_op_map_direct syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_bf_vm_op_map_direct(
        tls_t &mut_tls, page_pool_t &mut_page_pool, vm_pool_t const &vm_pool) noexcept
        -> syscall::bf_status_t
    {
        auto const vmid{get_allocated_vmid(mut_tls.ext_reg1, vm_pool)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        auto const phys{get_phys(mut_tls.ext_reg2)};
        if (bsl::unlikely(phys.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG2;
        }

        auto const virt{mut_tls.ext->map_page_direct(mut_tls, mut_page_pool, vmid, phys)};
        if (bsl::unlikely(virt.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        mut_tls.ext_reg0 = virt.get();
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vm_op_unmap_direct syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_bf_vm_op_unmap_direct(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        intrinsic_t const &intrinsic,
        vm_pool_t const &vm_pool) noexcept -> syscall::bf_status_t
    {
        auto const vmid{get_allocated_vmid(mut_tls.ext_reg1, vm_pool)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        auto const virt{get_direct_map_virt(mut_tls.ext_reg2)};
        if (bsl::unlikely(virt.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG2;
        }

        auto const ret{
            mut_tls.ext->unmap_page_direct(mut_tls, mut_page_pool, intrinsic, vmid, virt)};

        if (bsl::unlikely(!ret)) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_UNKNOWN;
        }

        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vm_op_unmap_direct_broadcast syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_bf_vm_op_unmap_direct_broadcast() noexcept -> syscall::bf_status_t
    {
        /// TODO:
        /// - We need to implement this. The reason this exists is that an
        ///   extension may wish to map memory, and then access it from any
        ///   PP. When this happens, the TLB will then contain the memory
        ///   associated with that PP.

        bsl::error() << "bf_vm_op_unmap_direct_broadcast currently not supported\n";
        return syscall::BF_STATUS_FAILURE_UNSUPPORTED;
    }

    /// <!-- description -->
    ///   @brief Implements the bf_vm_op_tlb_flush syscall
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param vm_pool the vm_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    syscall_bf_vm_op_tlb_flush(
        tls_t &mut_tls,
        intrinsic_t &mut_intrinsic,
        vm_pool_t const &vm_pool,
        vs_pool_t &mut_vs_pool) noexcept -> syscall::bf_status_t
    {
        auto const vmid{get_allocated_vmid(mut_tls.ext_reg1, vm_pool)};
        if (bsl::unlikely(vmid.is_invalid())) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_INPUT_REG1;
        }

        mut_vs_pool.tlb_flush(mut_tls, mut_intrinsic, vmid);
        return syscall::BF_STATUS_SUCCESS;
    }

    /// <!-- description -->
    ///   @brief Dispatches the bf_vm_op syscalls
    ///
    /// <!-- inputs/outputs -->
    ///   @param mut_tls the current TLS block
    ///   @param mut_page_pool the page_pool_t to use
    ///   @param mut_intrinsic the intrinsic_t to use
    ///   @param mut_vm_pool the vm_pool_t to use
    ///   @param vp_pool the vp_pool_t to use
    ///   @param mut_vs_pool the vs_pool_t to use
    ///   @param mut_ext_pool the ext_pool_t to use
    ///   @return Returns a bf_status_t containing success or failure
    ///
    [[nodiscard]] constexpr auto
    dispatch_syscall_bf_vm_op(
        tls_t &mut_tls,
        page_pool_t &mut_page_pool,
        intrinsic_t &mut_intrinsic,
        vm_pool_t &mut_vm_pool,
        vp_pool_t const &vp_pool,
        vs_pool_t &mut_vs_pool,
        ext_pool_t &mut_ext_pool) noexcept -> syscall::bf_status_t
    {
        if (bsl::unlikely(!verify_handle_for_current_ext(mut_tls))) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_FAILURE_INVALID_HANDLE;
        }

        if (bsl::unlikely(!is_the_active_ext_the_vmexit_ext(mut_tls))) {
            bsl::print<bsl::V>() << bsl::here();
            return syscall::BF_STATUS_INVALID_PERM_DENIED;
        }

        switch (syscall::bf_syscall_index(mut_tls.ext_syscall).get()) {
            case syscall::BF_VM_OP_CREATE_VM_IDX_VAL.get(): {
                auto const ret{
                    syscall_bf_vm_op_create_vm(mut_tls, mut_page_pool, mut_vm_pool, mut_ext_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VM_OP_DESTROY_VM_IDX_VAL.get(): {
                auto const ret{syscall_bf_vm_op_destroy_vm(
                    mut_tls, mut_page_pool, mut_vm_pool, vp_pool, mut_ext_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VM_OP_MAP_DIRECT_IDX_VAL.get(): {
                auto const ret{syscall_bf_vm_op_map_direct(mut_tls, mut_page_pool, mut_vm_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VM_OP_UNMAP_DIRECT_IDX_VAL.get(): {
                auto const ret{syscall_bf_vm_op_unmap_direct(
                    mut_tls, mut_page_pool, mut_intrinsic, mut_vm_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VM_OP_UNMAP_DIRECT_BROADCAST_IDX_VAL.get(): {
                auto const ret{syscall_bf_vm_op_unmap_direct_broadcast()};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            case syscall::BF_VM_OP_TLB_FLUSH_IDX_VAL.get(): {
                auto const ret{
                    syscall_bf_vm_op_tlb_flush(mut_tls, mut_intrinsic, mut_vm_pool, mut_vs_pool)};
                if (bsl::unlikely(ret != syscall::BF_STATUS_SUCCESS)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            default: {
                break;
            }
        }

        return report_syscall_unknown_unsupported(mut_tls);
    }
}

#endif
