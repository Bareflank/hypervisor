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

#ifndef VS_T_HPP
#define VS_T_HPP

#include <bf_constants.hpp>
#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace integration
{
    /// <!-- description -->
    ///   @brief Returns the masked version of the VMCS control fields
    ///
    /// <!-- inputs/outputs -->
    ///   @param val the value of the control fields read from the MSRs
    ///   @return The masked version of the control fields.
    ///
    [[nodiscard]] constexpr auto
    ctls_mask(bsl::safe_u64 const &val) noexcept -> bsl::safe_u64
    {
        constexpr auto mask{0x00000000FFFFFFFF_u64};
        constexpr auto shift{32_u64};
        return (val & mask) & (val >> shift);
    };

    /// @class integration::vs_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's notion of a VS
    ///
    class vs_t final
    {
        /// @brief stores the ID associated with this vs_t
        bsl::safe_u16 m_id{bsl::safe_u16::failure()};

    public:
        /// <!-- description -->
        ///   @brief Initializes this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param i the ID for this vs_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            gs_t &gs,
            tls_t &tls,
            syscall::bf_syscall_t &sys,
            intrinsic_t &intrinsic,
            bsl::safe_u16 const &i) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_id = i;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vs_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(gs_t &gs, tls_t &tls, syscall::bf_syscall_t &sys, intrinsic_t &intrinsic) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_id = bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Allocates a vs_t and returns it's ID
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vpid the ID of the VP to assign the vs_t to
        ///   @param ppid the ID of the PP to assign the vs_t to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        allocate(
            gs_t &gs,
            tls_t &tls,
            syscall::bf_syscall_t &sys,
            intrinsic_t &intrinsic,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(vpid);
            bsl::discard(ppid);

            ret = sys.bf_vs_op_init_as_root(m_id);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            constexpr auto vmcs_vpid_val{0x1_u64};
            ret = sys.bf_vs_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier, vmcs_vpid_val);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            constexpr auto vmcs_link_ptr_val{0xFFFFFFFFFFFFFFFF_u64};
            ret = sys.bf_vs_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer, vmcs_link_ptr_val);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            constexpr auto vmx_true_pinbased_ctls{0x48D_u32};
            constexpr auto vmx_true_procbased_ctls{0x48E_u32};
            constexpr auto vmx_true_exit_ctls{0x48F_u32};
            constexpr auto vmx_true_entry_ctls{0x490_u32};
            constexpr auto vmx_true_procbased_ctls2{0x48B_u32};

            bsl::safe_umx mut_ctls{};

            mut_ctls = sys.bf_intrinsic_op_rdmsr(vmx_true_pinbased_ctls);
            if (bsl::unlikely(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = sys.bf_vs_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls, ctls_mask(mut_ctls));
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            constexpr auto enable_msr_bitmaps{0x10000000_u64};
            constexpr auto enable_procbased_ctls2{0x80000000_u64};

            mut_ctls = sys.bf_intrinsic_op_rdmsr(vmx_true_procbased_ctls);
            if (bsl::unlikely(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ctls |= enable_msr_bitmaps;
            mut_ctls |= enable_procbased_ctls2;

            ret = sys.bf_vs_op_write(
                m_id,
                syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls,
                ctls_mask(mut_ctls));
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            mut_ctls = sys.bf_intrinsic_op_rdmsr(vmx_true_exit_ctls);
            if (bsl::unlikely(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = sys.bf_vs_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_vmexit_ctls, ctls_mask(mut_ctls));
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            mut_ctls = sys.bf_intrinsic_op_rdmsr(vmx_true_entry_ctls);
            if (bsl::unlikely(!mut_ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = sys.bf_vs_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_vmentry_ctls, ctls_mask(mut_ctls));
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            constexpr auto enable_vpid{0x00000020_u64};
            constexpr auto enable_rdtscp{0x00000008_u64};
            constexpr auto enable_invpcid{0x00001000_u64};
            constexpr auto enable_xsave{0x00100000_u64};
            constexpr auto enable_uwait{0x04000000_u64};

            mut_ctls = sys.bf_intrinsic_op_rdmsr(vmx_true_procbased_ctls2);
            if (bsl::unlikely(!ctls)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_ctls |= enable_vpid;
            mut_ctls |= enable_rdtscp;
            mut_ctls |= enable_invpcid;
            mut_ctls |= enable_xsave;
            mut_ctls |= enable_uwait;

            ret = sys.bf_vs_op_write(
                m_id,
                syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls,
                ctls_mask(mut_ctls));
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = sys.bf_vs_op_write(
                m_id, syscall::bf_reg_t::bf_reg_t_address_of_msr_bitmaps, gs.msr_bitmap_phys);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return bsl::errc_success;
        }
    };
}

#endif
