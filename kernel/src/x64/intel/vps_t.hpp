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

#ifndef VPS_T_HPP
#define VPS_T_HPP

#include <allocate_tags.hpp>
#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <general_purpose_regs_t.hpp>
#include <intrinsic_t.hpp>
#include <page_pool_t.hpp>
#include <tls_t.hpp>
#include <vmcs_missing_registers_t.hpp>
#include <vmcs_t.hpp>
#include <vmexit_log_t.hpp>

#include <bsl/array.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/finally.hpp>
#include <bsl/is_same.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/string_view.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace mk
{
    /// @brief entry point prototype
    extern "C" void intrinsic_vmexit(void) noexcept;

    /// @brief defines the IA32_VMX_BASIC MSR
    constexpr auto IA32_VMX_BASIC{0x480_u32};
    /// @brief defines the IA32_PAT MSR
    constexpr auto IA32_PAT{0x277_u32};
    /// @brief defines the IA32_SYSENTER_CS MSR
    constexpr auto IA32_SYSENTER_CS{0x174_u32};
    /// @brief defines the IA32_SYSENTER_ESP MSR
    constexpr auto IA32_SYSENTER_ESP{0x175_u32};
    /// @brief defines the IA32_SYSENTER_EIP MSR
    constexpr auto IA32_SYSENTER_EIP{0x176_u32};
    /// @brief defines the IA32_EFER MSR
    constexpr auto IA32_EFER{0xC0000080_u32};
    /// @brief defines the IA32_STAR MSR
    constexpr auto IA32_STAR{0xC0000081_u32};
    /// @brief defines the IA32_LSTAR MSR
    constexpr auto IA32_LSTAR{0xC0000082_u32};
    /// @brief defines the IA32_CSTAR MSR
    constexpr auto IA32_CSTAR{0xC0000083_u32};
    /// @brief defines the IA32_FMASK MSR
    constexpr auto IA32_FMASK{0xC0000084_u32};
    /// @brief defines the IA32_FS_BASE MSR
    constexpr auto IA32_FS_BASE{0xC0000100_u32};
    /// @brief defines the IA32_GS_BASE MSR
    constexpr auto IA32_GS_BASE{0xC0000101_u32};
    /// @brief defines the IA32_KERNEL_GS_BASE MSR
    constexpr auto IA32_KERNEL_GS_BASE{0xC0000102_u32};

    /// @class mk::vps_t
    ///
    /// <!-- description -->
    ///   @brief Defines the microkernel's notion of a VPS.
    ///
    class vps_t final
    {
        /// @brief stores the ID associated with this vp_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::failure()};
        /// @brief stores whether or not this vp_t is allocated.
        allocated_status_t m_allocated{allocated_status_t::deallocated};
        /// @brief stores the ID of the VP this vps_t is assigned to
        bsl::safe_uint16 m_assigned_vpid{syscall::BF_INVALID_ID};
        /// @brief stores the ID of the PP this vp_t is assigned to
        bsl::safe_uint16 m_assigned_ppid{syscall::BF_INVALID_ID};
        /// @brief stores the ID of the PP this vp_t is active on
        bsl::safe_uint16 m_active_ppid{bsl::safe_uint16::failure()};

        /// @brief stores a pointer to the guest vmcs being managed by this VPS
        vmcs_t *m_vmcs{};
        /// @brief stores the physical address of the guest vmcs
        bsl::safe_uintmax m_vmcs_phys{bsl::safe_uintmax::failure()};
        /// @brief stores the rest of the state the vmcs doesn't
        vmcs_missing_registers_t m_vmcs_missing_registers{};
        /// @brief stores the general purpose registers
        general_purpose_regs_t m_gprs{};

        /// <!-- description -->
        ///   @brief Stores the provided ES segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        set_es_segment_descriptor(
            intrinsic_t &intrinsic, loader::state_save_t const &state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            constexpr auto unused{0_u16};
            if (unused == state.es_selector) {
                ret = intrinsic.vmwrite16(VMCS_GUEST_ES_SELECTOR, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_ES_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_ES_LIMIT, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_ES_BASE, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }
            else {
                ret = intrinsic.vmwrite16(VMCS_GUEST_ES_SELECTOR, state.es_selector);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret =
                    intrinsic.vmwrite32(VMCS_GUEST_ES_ACCESS_RIGHTS, bsl::to_u32(state.es_attrib));
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_ES_LIMIT, state.es_limit);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_ES_BASE, state.es_base);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided CS segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        set_cs_segment_descriptor(
            intrinsic_t &intrinsic, loader::state_save_t const &state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            constexpr auto unused{0_u16};
            if (unused == state.cs_selector) {
                ret = intrinsic.vmwrite16(VMCS_GUEST_CS_SELECTOR, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_CS_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_CS_LIMIT, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_CS_BASE, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }
            else {
                ret = intrinsic.vmwrite16(VMCS_GUEST_CS_SELECTOR, state.cs_selector);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret =
                    intrinsic.vmwrite32(VMCS_GUEST_CS_ACCESS_RIGHTS, bsl::to_u32(state.cs_attrib));
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_CS_LIMIT, state.cs_limit);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_CS_BASE, state.cs_base);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided SS segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        set_ss_segment_descriptor(
            intrinsic_t &intrinsic, loader::state_save_t const &state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            constexpr auto unused{0_u16};
            if (unused == state.ss_selector) {
                ret = intrinsic.vmwrite16(VMCS_GUEST_SS_SELECTOR, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_SS_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_SS_LIMIT, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_SS_BASE, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }
            else {
                ret = intrinsic.vmwrite16(VMCS_GUEST_SS_SELECTOR, state.ss_selector);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret =
                    intrinsic.vmwrite32(VMCS_GUEST_SS_ACCESS_RIGHTS, bsl::to_u32(state.ss_attrib));
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_SS_LIMIT, state.ss_limit);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_SS_BASE, state.ss_base);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided DS segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        set_ds_segment_descriptor(
            intrinsic_t &intrinsic, loader::state_save_t const &state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            constexpr auto unused{0_u16};
            if (unused == state.ds_selector) {
                ret = intrinsic.vmwrite16(VMCS_GUEST_DS_SELECTOR, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_DS_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_DS_LIMIT, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_DS_BASE, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }
            else {
                ret = intrinsic.vmwrite16(VMCS_GUEST_DS_SELECTOR, state.ds_selector);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret =
                    intrinsic.vmwrite32(VMCS_GUEST_DS_ACCESS_RIGHTS, bsl::to_u32(state.ds_attrib));
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_DS_LIMIT, state.ds_limit);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_DS_BASE, state.ds_base);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided FS segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        set_fs_segment_descriptor(
            intrinsic_t &intrinsic, loader::state_save_t const &state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            constexpr auto unused{0_u16};
            if (unused == state.fs_selector) {
                ret = intrinsic.vmwrite16(VMCS_GUEST_FS_SELECTOR, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_FS_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_FS_LIMIT, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_FS_BASE, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }
            else {
                ret = intrinsic.vmwrite16(VMCS_GUEST_FS_SELECTOR, state.fs_selector);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret =
                    intrinsic.vmwrite32(VMCS_GUEST_FS_ACCESS_RIGHTS, bsl::to_u32(state.fs_attrib));
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_FS_LIMIT, state.fs_limit);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_FS_BASE, state.fs_base);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided GS segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        set_gs_segment_descriptor(
            intrinsic_t &intrinsic, loader::state_save_t const &state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            constexpr auto unused{0_u16};
            if (unused == state.gs_selector) {
                ret = intrinsic.vmwrite16(VMCS_GUEST_GS_SELECTOR, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_GS_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_GS_LIMIT, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_GS_BASE, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }
            else {
                ret = intrinsic.vmwrite16(VMCS_GUEST_GS_SELECTOR, state.gs_selector);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret =
                    intrinsic.vmwrite32(VMCS_GUEST_GS_ACCESS_RIGHTS, bsl::to_u32(state.gs_attrib));
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_GS_LIMIT, state.gs_limit);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_GS_BASE, state.gs_base);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided LDTR segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        set_ldtr_segment_descriptor(
            intrinsic_t &intrinsic, loader::state_save_t const &state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            constexpr auto unused{0_u16};
            if (unused == state.ldtr_selector) {
                ret = intrinsic.vmwrite16(VMCS_GUEST_LDTR_SELECTOR, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_LDTR_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_LDTR_LIMIT, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_LDTR_BASE, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }
            else {
                ret = intrinsic.vmwrite16(VMCS_GUEST_LDTR_SELECTOR, state.ldtr_selector);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(
                    VMCS_GUEST_LDTR_ACCESS_RIGHTS, bsl::to_u32(state.ldtr_attrib));
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_LDTR_LIMIT, state.ldtr_limit);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_LDTR_BASE, state.ldtr_base);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided TR segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        set_tr_segment_descriptor(
            intrinsic_t &intrinsic, loader::state_save_t const &state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            constexpr auto unused{0_u16};
            if (unused == state.tr_selector) {
                ret = intrinsic.vmwrite16(VMCS_GUEST_TR_SELECTOR, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_TR_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_TR_LIMIT, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_TR_BASE, {});
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }
            else {
                ret = intrinsic.vmwrite16(VMCS_GUEST_TR_SELECTOR, state.tr_selector);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret =
                    intrinsic.vmwrite32(VMCS_GUEST_TR_ACCESS_RIGHTS, bsl::to_u32(state.tr_attrib));
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite32(VMCS_GUEST_TR_LIMIT, state.tr_limit);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                ret = intrinsic.vmwrite64(VMCS_GUEST_TR_BASE, state.tr_base);
                if (bsl::unlikely_assert(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the ES segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        get_es_segment_descriptor(intrinsic_t &intrinsic, loader::state_save_t &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = intrinsic.vmread16(VMCS_GUEST_ES_SELECTOR, selector.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_ES_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_ES_LIMIT, limit.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_ES_BASE, base.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state.es_selector = {};
                state.es_attrib = {};
                state.es_limit = {};
                state.es_base = {};
            }
            else {
                state.es_selector = selector.get();
                state.es_attrib = bsl::to_u16(access_rights).get();
                state.es_limit = limit.get();
                state.es_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the CS segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        get_cs_segment_descriptor(intrinsic_t &intrinsic, loader::state_save_t &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = intrinsic.vmread16(VMCS_GUEST_CS_SELECTOR, selector.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_CS_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_CS_LIMIT, limit.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_CS_BASE, base.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state.cs_selector = {};
                state.cs_attrib = {};
                state.cs_limit = {};
                state.cs_base = {};
            }
            else {
                state.cs_selector = selector.get();
                state.cs_attrib = bsl::to_u16(access_rights).get();
                state.cs_limit = limit.get();
                state.cs_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the SS segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        get_ss_segment_descriptor(intrinsic_t &intrinsic, loader::state_save_t &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = intrinsic.vmread16(VMCS_GUEST_SS_SELECTOR, selector.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_SS_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_SS_LIMIT, limit.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_SS_BASE, base.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state.ss_selector = {};
                state.ss_attrib = {};
                state.ss_limit = {};
                state.ss_base = {};
            }
            else {
                state.ss_selector = selector.get();
                state.ss_attrib = bsl::to_u16(access_rights).get();
                state.ss_limit = limit.get();
                state.ss_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the DS segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        get_ds_segment_descriptor(intrinsic_t &intrinsic, loader::state_save_t &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = intrinsic.vmread16(VMCS_GUEST_DS_SELECTOR, selector.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_DS_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_DS_LIMIT, limit.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_DS_BASE, base.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state.ds_selector = {};
                state.ds_attrib = {};
                state.ds_limit = {};
                state.ds_base = {};
            }
            else {
                state.ds_selector = selector.get();
                state.ds_attrib = bsl::to_u16(access_rights).get();
                state.ds_limit = limit.get();
                state.ds_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the GS segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        get_gs_segment_descriptor(intrinsic_t &intrinsic, loader::state_save_t &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = intrinsic.vmread16(VMCS_GUEST_GS_SELECTOR, selector.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_GS_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_GS_LIMIT, limit.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_GS_BASE, base.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state.gs_selector = {};
                state.gs_attrib = {};
                state.gs_limit = {};
                state.gs_base = {};
            }
            else {
                state.gs_selector = selector.get();
                state.gs_attrib = bsl::to_u16(access_rights).get();
                state.gs_limit = limit.get();
                state.gs_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the FS segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        get_fs_segment_descriptor(intrinsic_t &intrinsic, loader::state_save_t &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = intrinsic.vmread16(VMCS_GUEST_FS_SELECTOR, selector.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_FS_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_FS_LIMIT, limit.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_FS_BASE, base.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state.fs_selector = {};
                state.fs_attrib = {};
                state.fs_limit = {};
                state.fs_base = {};
            }
            else {
                state.fs_selector = selector.get();
                state.fs_attrib = bsl::to_u16(access_rights).get();
                state.fs_limit = limit.get();
                state.fs_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the LDTR segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        get_ldtr_segment_descriptor(intrinsic_t &intrinsic, loader::state_save_t &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = intrinsic.vmread16(VMCS_GUEST_LDTR_SELECTOR, selector.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_LDTR_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_LDTR_LIMIT, limit.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_LDTR_BASE, base.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state.ldtr_selector = {};
                state.ldtr_attrib = {};
                state.ldtr_limit = {};
                state.ldtr_base = {};
            }
            else {
                state.ldtr_selector = selector.get();
                state.ldtr_attrib = bsl::to_u16(access_rights).get();
                state.ldtr_limit = limit.get();
                state.ldtr_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the TR segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        get_tr_segment_descriptor(intrinsic_t &intrinsic, loader::state_save_t &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = intrinsic.vmread16(VMCS_GUEST_TR_SELECTOR, selector.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_TR_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread32(VMCS_GUEST_TR_LIMIT, limit.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_TR_BASE, base.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state.tr_selector = {};
                state.tr_attrib = {};
                state.tr_limit = {};
                state.tr_base = {};
            }
            else {
                state.tr_selector = selector.get();
                state.tr_attrib = bsl::to_u16(access_rights).get();
                state.tr_limit = limit.get();
                state.tr_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Ensures that this VPS is loaded
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        ensure_this_vps_is_loaded(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (m_id == tls.loaded_vpsid) {
                return bsl::errc_success;
            }

            ret = intrinsic.vmload(&m_vmcs_phys);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            tls.loaded_vpsid = m_id.get();
            return ret;
        }

        /// <!-- description -->
        ///   @brief This is executed on each core when a VPS is first
        ///     allocated, and ensures the VMCS contains the current host
        ///     states of the CPU it is running on. We don't use the state
        ///     that the loader provides as this state can change as the
        ///     microkernel completes it's bootstrapping process.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        init_vmcs(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            auto *const state{tls.mk_state};

            auto const revision_id{intrinsic.rdmsr(IA32_VMX_BASIC)};
            if (bsl::unlikely_assert(!revision_id)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_vmcs->revision_id = bsl::to_u32_unsafe(revision_id).get();

            ret = this->ensure_this_vps_is_loaded(tls, intrinsic);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite16(VMCS_HOST_ES_SELECTOR, intrinsic.es_selector());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite16(VMCS_HOST_CS_SELECTOR, intrinsic.cs_selector());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite16(VMCS_HOST_SS_SELECTOR, intrinsic.ss_selector());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite16(VMCS_HOST_DS_SELECTOR, intrinsic.ds_selector());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite16(VMCS_HOST_FS_SELECTOR, intrinsic.fs_selector());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite16(VMCS_HOST_GS_SELECTOR, intrinsic.gs_selector());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite16(VMCS_HOST_TR_SELECTOR, intrinsic.tr_selector());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_IA32_PAT, intrinsic.rdmsr(IA32_PAT));
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_IA32_EFER, intrinsic.rdmsr(IA32_EFER));
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret =
                intrinsic.vmwrite64(VMCS_HOST_IA32_SYSENTER_CS, intrinsic.rdmsr(IA32_SYSENTER_CS));
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_CR0, intrinsic.cr0());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_CR3, intrinsic.cr3());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_CR4, intrinsic.cr4());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_FS_BASE, intrinsic.rdmsr(IA32_FS_BASE));
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_GS_BASE, intrinsic.rdmsr(IA32_GS_BASE));
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_TR_BASE, state->tr_base);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_GDTR_BASE, bsl::to_umax(state->gdtr.base));
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_IDTR_BASE, bsl::to_umax(state->idtr.base));
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(
                VMCS_HOST_IA32_SYSENTER_ESP, intrinsic.rdmsr(IA32_SYSENTER_ESP));
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(
                VMCS_HOST_IA32_SYSENTER_EIP, intrinsic.rdmsr(IA32_SYSENTER_EIP));
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_HOST_RIP, bsl::to_umax(&intrinsic_vmexit));
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            m_vmcs_missing_registers.host_ia32_star =              // --
                intrinsic.rdmsr(IA32_STAR).get();                  // --
            m_vmcs_missing_registers.host_ia32_lstar =             // --
                intrinsic.rdmsr(IA32_LSTAR).get();                 // --
            m_vmcs_missing_registers.host_ia32_cstar =             // --
                intrinsic.rdmsr(IA32_CSTAR).get();                 // --
            m_vmcs_missing_registers.host_ia32_fmask =             // --
                intrinsic.rdmsr(IA32_FMASK).get();                 // --
            m_vmcs_missing_registers.host_ia32_kernel_gs_base =    // --
                intrinsic.rdmsr(IA32_KERNEL_GS_BASE).get();        // --

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Dumps the contents of a field
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of field to dump
        ///   @param str the name of the field
        ///   @param val the field to dump
        ///
        template<typename T>
        constexpr void
        dump(bsl::string_view const &str, bsl::safe_integral<T> const &val) const noexcept
        {
            auto const *rowcolor{bsl::rst};

            if (val.is_zero()) {
                rowcolor = bsl::blk;
            }
            else {
                bsl::touch();
            }

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<40s", str};
            bsl::print() << bsl::ylw << "| ";

            if (val) {
                if constexpr (bsl::is_same<T, bsl::uint8>::value) {
                    bsl::print() << rowcolor << "       " << bsl::hex(val) << "        ";
                }

                if constexpr (bsl::is_same<T, bsl::uint16>::value) {
                    bsl::print() << rowcolor << "      " << bsl::hex(val) << "       ";
                }

                if constexpr (bsl::is_same<T, bsl::uint32>::value) {
                    bsl::print() << rowcolor << "    " << bsl::hex(val) << "     ";
                }

                if constexpr (bsl::is_same<T, bsl::uint64>::value) {
                    bsl::print() << rowcolor << bsl::hex(val) << ' ';
                }
            }
            else {
                bsl::print() << bsl::blk << bsl::fmt{"^19s", "unsupported"};
            }

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the ID for this vps_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(bsl::safe_uint16 const &i) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(m_id)) {
                bsl::error() << "vps_t already initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!i)) {
                bsl::error() << "invalid id\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == i)) {
                bsl::error() << "id "                                                  // --
                             << bsl::hex(i)                                            // --
                             << " is invalid and cannot be used for initialization"    // --
                             << bsl::endl                                              // --
                             << bsl::here();                                           // --

                return bsl::errc_precondition;
            }

            m_id = i;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vp_t. Note that if this function fails,
        ///     the microkernel is left in a corrupt state and all use of the
        ///     vp_t after calling this function will results in UB.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        release(tls_t &tls, page_pool_t &page_pool) noexcept -> bsl::errc_type
        {
            if (this->is_zombie()) {
                return bsl::errc_success;
            }

            tls.state_reversal_required = true;
            bsl::finally zombify_on_error{[this]() noexcept -> void {
                this->zombify();
            }};

            if (bsl::unlikely(m_active_ppid)) {
                bsl::error() << "vp "                      // --
                             << bsl::hex(m_id)             // --
                             << " is active on pp "        // --
                             << bsl::hex(m_active_ppid)    // --
                             << " and therefore vp "       // --
                             << bsl::hex(m_id)             // --
                             << " cannot be destroyed"     // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_failure;
            }

            m_gprs = {};
            m_vmcs_missing_registers = {};

            m_vmcs_phys = bsl::safe_uintmax::failure();
            page_pool.deallocate(tls, m_vmcs, ALLOCATE_TAG_VMCS);
            m_vmcs = {};

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vpid = syscall::BF_INVALID_ID;
            m_allocated = allocated_status_t::deallocated;
            m_id = bsl::safe_uint16::failure();

            zombify_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vps_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_uint16 const &
        {
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param page_pool the page pool to use
        ///   @param vpid The ID of the VP to assign the newly created VP to
        ///   @param ppid The ID of the PP to assign the newly created VP to
        ///   @return Returns ID of the newly allocated vps
        ///
        [[nodiscard]] constexpr auto
        allocate(
            tls_t &tls,
            intrinsic_t &intrinsic,
            page_pool_t &page_pool,
            bsl::safe_uint16 const &vpid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::safe_uint16
        {
            bsl::errc_type ret{};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(!vpid)) {
                bsl::error() << "invalid vpid\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(syscall::BF_INVALID_ID == vpid)) {
                bsl::error() << "vp "                                               // --
                             << bsl::hex(vpid)                                      // --
                             << " is invalid and a vps cannot be assigned to it"    // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

                return bsl::safe_uint16::failure();
            }

            // if (bsl::unlikely(vp_pool.is_zombie(tls, vpid))) {
            //     bsl::error() << "vp "                                                // --
            //                  << bsl::hex(vpid)                                       // --
            //                  << " is a zombie and a vps cannot be assigned to it"    // --
            //                  << bsl::endl                                            // --
            //                  << bsl::here();                                         // --

            //     return bsl::safe_uint16::failure();
            // }

            // if (bsl::unlikely(vp_pool.is_deallocated(tls, vpid))) {
            //     bsl::error() << "vp "                                                         // --
            //                  << bsl::hex(vpid)                                                // --
            //                  << " has not been created and a vps cannot be assigned to it"    // --
            //                  << bsl::endl                                                     // --
            //                  << bsl::here();                                                  // --

            //     return bsl::safe_uint16::failure();
            // }

            if (bsl::unlikely_assert(!ppid)) {
                bsl::error() << "invalid ppid\n" << bsl::here();
                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(syscall::BF_INVALID_ID == ppid)) {
                bsl::error() << "pp "                                               // --
                             << bsl::hex(ppid)                                      // --
                             << " is invalid and a vps cannot be assigned to it"    // --
                             << bsl::endl                                           // --
                             << bsl::here();                                        // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely(!(ppid < tls.online_pps))) {
                bsl::error() << "pp "                                                  // --
                             << bsl::hex(ppid)                                         // --
                             << " is not less than the total number of online pps "    // --
                             << bsl::hex(tls.online_pps)                               // --
                             << " and a vps cannot be assigned to it"                  // --
                             << bsl::endl                                              // --
                             << bsl::here();                                           // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vps "                                    // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be allocated"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::safe_uint16::failure();
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::allocated)) {
                bsl::error() << "vps "                                           // --
                             << bsl::hex(m_id)                                   // --
                             << " is already allocated and cannot be created"    // --
                             << bsl::endl                                        // --
                             << bsl::here();                                     // --

                return bsl::safe_uint16::failure();
            }

            tls.state_reversal_required = true;
            tls.log_vpsid = m_id.get();

            bsl::finally cleanup_on_error{[this, &tls, &page_pool]() noexcept -> void {
                m_vmcs_phys = bsl::safe_uintmax::failure();
                page_pool.deallocate(tls, m_vmcs, ALLOCATE_TAG_VMCS);
                m_vmcs = {};
            }};

            m_vmcs = page_pool.template allocate<vmcs_t>(tls, ALLOCATE_TAG_VMCS);
            if (bsl::unlikely(nullptr == m_vmcs)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            m_vmcs_phys = page_pool.virt_to_phys(m_vmcs);
            if (bsl::unlikely_assert(!m_vmcs_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            ret = this->init_vmcs(tls, intrinsic);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            m_assigned_vpid = vpid;
            m_assigned_ppid = ppid;
            m_allocated = allocated_status_t::allocated;

            cleanup_on_error.ignore();
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Deallocates this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(tls_t &tls, page_pool_t &page_pool) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated == allocated_status_t::zombie)) {
                bsl::error() << "vps "                                    // --
                             << bsl::hex(m_id)                            // --
                             << " is a zombie and cannot be destroyed"    // --
                             << bsl::endl                                 // --
                             << bsl::here();                              // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                               // --
                             << bsl::hex(m_id)                                       // --
                             << " is already deallocated and cannot be destroyed"    // --
                             << bsl::endl                                            // --
                             << bsl::here();                                         // --

                return bsl::errc_precondition;
            }

            tls.state_reversal_required = true;
            bsl::finally zombify_on_error{[this]() noexcept -> void {
                this->zombify();
            }};

            if (bsl::unlikely(m_active_ppid)) {
                bsl::error() << "vps "                     // --
                             << bsl::hex(m_id)             // --
                             << " is active on pp "        // --
                             << bsl::hex(m_active_ppid)    // --
                             << " and therefore vps "      // --
                             << bsl::hex(m_id)             // --
                             << " cannot be destroyed"     // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_failure;
            }

            m_gprs = {};
            m_vmcs_missing_registers = {};

            m_vmcs_phys = bsl::safe_uintmax::failure();
            page_pool.deallocate(tls, m_vmcs, ALLOCATE_TAG_VMCS);
            m_vmcs = {};

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vpid = syscall::BF_INVALID_ID;
            m_allocated = allocated_status_t::deallocated;

            zombify_on_error.ignore();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vps_t's status as zombified, meaning it is no
        ///     longer usable.
        ///
        constexpr void
        zombify() noexcept
        {
            if (bsl::unlikely_assert(!m_id)) {
                return;
            }

            if (m_allocated == allocated_status_t::zombie) {
                return;
            }

            bsl::alert() << "vps "                   // --
                         << bsl::hex(m_id)           // --
                         << " has been zombified"    // --
                         << bsl::endl;               // --

            m_allocated = allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is a zombie, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vps_t is a zombie, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_zombie() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::zombie;
        }

        /// <!-- description -->
        ///   @brief Sets this vps_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_active(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.active_vpid != m_assigned_vpid)) {
                bsl::error() << "vps "                                 // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to vp "                  // --
                             << bsl::hex(m_assigned_vpid)              // --
                             << " and cannot be activated with vp "    // --
                             << bsl::hex(tls.active_vpid)              // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vps "                               // --
                             << bsl::hex(m_id)                       // --
                             << " is assigned to pp "                // --
                             << bsl::hex(m_assigned_ppid)            // --
                             << " and cannot be activated on pp "    // --
                             << bsl::hex(tls.ppid)                   // --
                             << bsl::endl                            // --
                             << bsl::here();                         // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID != tls.active_vpsid)) {
                bsl::error() << "vps "                        // --
                             << bsl::hex(tls.active_vpsid)    // --
                             << " is still active on pp "     // --
                             << bsl::hex(tls.ppid)            // --
                             << bsl::endl                     // --
                             << bsl::here();                  // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_active_ppid)) {
                bsl::error() << "vps "                                 // --
                             << bsl::hex(m_id)                         // --
                             << " is already the active vps on pp "    // --
                             << bsl::hex(m_active_ppid)                // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, m_gprs.rax);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, m_gprs.rbx);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, m_gprs.rcx);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, m_gprs.rdx);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, m_gprs.rbp);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, m_gprs.rsi);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, m_gprs.rdi);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, m_gprs.r8);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, m_gprs.r9);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, m_gprs.r10);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, m_gprs.r11);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, m_gprs.r12);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, m_gprs.r13);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, m_gprs.r14);
            intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, m_gprs.r15);

            tls.active_vpsid = m_id.get();
            m_active_ppid = tls.ppid;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vps_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_inactive(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
        {
            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(m_allocated == allocated_status_t::deallocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == tls.active_vpsid)) {
                bsl::error() << "vps "                     // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(tls.ppid)         // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(tls.active_vpsid != m_id)) {
                bsl::error() << "vps "                        // --
                             << bsl::hex(tls.active_vpsid)    // --
                             << " is still active on pp "     // --
                             << bsl::hex(tls.ppid)            // --
                             << bsl::endl                     // --
                             << bsl::here();                  // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!m_active_ppid)) {
                bsl::error() << "vps "               // --
                             << bsl::hex(m_id)       // --
                             << " is not active "    // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(tls.ppid != m_active_ppid)) {
                bsl::error() << "vps "                     // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(tls.ppid)         // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

            m_gprs.rax = intrinsic.tls_reg(syscall::TLS_OFFSET_RAX).get();
            m_gprs.rbx = intrinsic.tls_reg(syscall::TLS_OFFSET_RBX).get();
            m_gprs.rcx = intrinsic.tls_reg(syscall::TLS_OFFSET_RCX).get();
            m_gprs.rdx = intrinsic.tls_reg(syscall::TLS_OFFSET_RDX).get();
            m_gprs.rbp = intrinsic.tls_reg(syscall::TLS_OFFSET_RBP).get();
            m_gprs.rsi = intrinsic.tls_reg(syscall::TLS_OFFSET_RSI).get();
            m_gprs.rdi = intrinsic.tls_reg(syscall::TLS_OFFSET_RDI).get();
            m_gprs.r8 = intrinsic.tls_reg(syscall::TLS_OFFSET_R8).get();
            m_gprs.r9 = intrinsic.tls_reg(syscall::TLS_OFFSET_R9).get();
            m_gprs.r10 = intrinsic.tls_reg(syscall::TLS_OFFSET_R10).get();
            m_gprs.r11 = intrinsic.tls_reg(syscall::TLS_OFFSET_R11).get();
            m_gprs.r12 = intrinsic.tls_reg(syscall::TLS_OFFSET_R12).get();
            m_gprs.r13 = intrinsic.tls_reg(syscall::TLS_OFFSET_R13).get();
            m_gprs.r14 = intrinsic.tls_reg(syscall::TLS_OFFSET_R14).get();
            m_gprs.r15 = intrinsic.tls_reg(syscall::TLS_OFFSET_R15).get();

            tls.active_vpsid = syscall::BF_INVALID_ID.get();
            m_active_ppid = bsl::safe_uint16::failure();

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP that this vps_t is still active
        ///     on. If the vps_t is inactive, this function returns
        ///     bsl::safe_uint16::failure()
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns the ID of the PP that this vps_t is still active
        ///     on. If the vps_t is inactive, this function returns
        ///     bsl::safe_uint16::failure()
        ///
        [[nodiscard]] constexpr auto
        is_active(tls_t &tls) const noexcept -> bsl::safe_uint16
        {
            bsl::discard(tls);
            return m_active_ppid;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vps_t is active on the current PP,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns true if this vps_t is active on the current PP,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_current_pp(tls_t &tls) const noexcept -> bool
        {
            return tls.ppid == m_active_ppid;
        }

        /// <!-- description -->
        ///   @brief Migrates this vps_t from one PP to another. This should
        ///     only be called by the run ABI when the VP and VPS's assigned
        ///     ppids do not match. The VPS should always match the assigned
        ///     VP's ID. If it doesn't we need to migrate the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param ppid the ID of the PP to migrate to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        migrate(tls_t &tls, intrinsic_t &intrinsic, bsl::safe_uint16 const &ppid) noexcept
            -> bsl::errc_type
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(ppid);

            // if (bsl::unlikely_assert(!m_id)) {
            //     bsl::error() << "vps_t not initialized\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(!m_allocated)) {
            //     bsl::error() << "vps "                    // --
            //                  << bsl::hex(m_id)            // --
            //                  << " was never allocated"    // --
            //                  << bsl::endl                 // --
            //                  << bsl::here();              // --

            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(!ppid)) {
            //     bsl::error() << "invalid ppid\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(syscall::BF_INVALID_ID == ppid)) {
            //     bsl::error() << "invalid ppid\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(!(ppid < tls.online_pps))) {
            //     bsl::error() << "invalid ppid\n" << bsl::here();
            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(tls.ppid != ppid)) {
            //     bsl::error() << "vps "                         // --
            //                  << bsl::hex(m_id)                 // --
            //                  << " is being migrated to pp "    // --
            //                  << bsl::hex(ppid)                 // --
            //                  << " by pp "                      // --
            //                  << bsl::hex(tls.ppid)             // --
            //                  << " which is not allowed "       // --
            //                  << bsl::endl                      // --
            //                  << bsl::here();                   // --

            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(ppid == m_assigned_ppid)) {
            //     bsl::error() << "vps "                             // --
            //                  << bsl::hex(m_id)                     // --
            //                  << " is already assigned to a pp "    // --
            //                  << bsl::hex(m_assigned_ppid)          // --
            //                  << bsl::endl                          // --
            //                  << bsl::here();                       // --

            //     return bsl::errc_failure;
            // }

            // if (bsl::unlikely(syscall::BF_INVALID_ID != m_active_ppid)) {
            //     bsl::error() << "vps "                       // --
            //                  << bsl::hex(m_id)               // --
            //                  << " is still active on pp "    // --
            //                  << bsl::hex(m_active_ppid)      // --
            //                  << bsl::endl                    // --
            //                  << bsl::here();                 // --

            //     return bsl::errc_failure;
            // }

            // m_guest_vmcb->vmcb_clean_bits = {};
            // m_assigned_ppid = ppid;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VP this vp_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VP this vp_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_vp() const noexcept -> bsl::safe_uint16
        {
            if (bsl::unlikely(syscall::BF_INVALID_ID == m_assigned_vpid)) {
                return bsl::safe_uint16::failure();
            }

            return m_assigned_vpid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vp_t is assigned to
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vp_t is assigned to
        ///
        [[nodiscard]] constexpr auto
        assigned_pp() const noexcept -> bsl::safe_uint16
        {
            if (bsl::unlikely(syscall::BF_INVALID_ID == m_assigned_ppid)) {
                return bsl::safe_uint16::failure();
            }

            return m_assigned_ppid;
        }

        /// <!-- description -->
        ///   @brief Stores the provided state in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        [[nodiscard]] constexpr auto
        state_save_to_vps(
            tls_t &tls, intrinsic_t &intrinsic, loader::state_save_t const &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            ret = this->ensure_this_vps_is_loaded(tls, intrinsic);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            if (tls.active_vpsid == m_id) {
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, state.rax);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, state.rbx);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, state.rcx);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, state.rdx);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, state.rbp);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, state.rsi);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, state.rdi);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, state.r8);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, state.r9);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, state.r10);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, state.r11);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, state.r12);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, state.r13);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, state.r14);
                intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, state.r15);
            }
            else {
                m_gprs.rax = state.rax;
                m_gprs.rbx = state.rbx;
                m_gprs.rcx = state.rcx;
                m_gprs.rdx = state.rdx;
                m_gprs.rbp = state.rbp;
                m_gprs.rsi = state.rsi;
                m_gprs.rdi = state.rdi;
                m_gprs.r8 = state.r8;
                m_gprs.r9 = state.r9;
                m_gprs.r10 = state.r10;
                m_gprs.r11 = state.r11;
                m_gprs.r12 = state.r12;
                m_gprs.r13 = state.r13;
                m_gprs.r14 = state.r14;
                m_gprs.r15 = state.r15;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_RSP, state.rsp);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_RIP, state.rip);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_RFLAGS, state.rflags);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            auto const gdtr_limit{bsl::to_u32(state.gdtr.limit)};
            ret = intrinsic.vmwrite32(VMCS_GUEST_GDTR_LIMIT, gdtr_limit);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            auto const gdtr_base{bsl::to_umax(state.gdtr.base)};
            ret = intrinsic.vmwrite64(VMCS_GUEST_GDTR_BASE, gdtr_base);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            auto const idtr_limit{bsl::to_u32(state.idtr.limit)};
            ret = intrinsic.vmwrite32(VMCS_GUEST_IDTR_LIMIT, idtr_limit);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            auto const idtr_base{bsl::to_umax(state.idtr.base)};
            ret = intrinsic.vmwrite64(VMCS_GUEST_IDTR_BASE, idtr_base);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->set_es_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->set_cs_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->set_ss_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->set_ds_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->set_fs_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->set_gs_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->set_ldtr_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->set_tr_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_CR0, state.cr0);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            m_vmcs_missing_registers.cr2 = state.cr2;

            ret = intrinsic.vmwrite64(VMCS_GUEST_CR3, state.cr3);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_CR4, state.cr4);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            m_vmcs_missing_registers.dr6 = state.dr6;

            ret = intrinsic.vmwrite64(VMCS_GUEST_DR7, state.dr7);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_IA32_EFER, state.ia32_efer);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            m_vmcs_missing_registers.guest_ia32_star = state.ia32_star;
            m_vmcs_missing_registers.guest_ia32_lstar = state.ia32_lstar;
            m_vmcs_missing_registers.guest_ia32_cstar = state.ia32_cstar;
            m_vmcs_missing_registers.guest_ia32_fmask = state.ia32_fmask;

            ret = intrinsic.vmwrite64(VMCS_GUEST_FS_BASE, state.ia32_fs_base);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_GS_BASE, state.ia32_gs_base);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            m_vmcs_missing_registers.guest_ia32_kernel_gs_base = state.ia32_kernel_gs_base;

            ret = intrinsic.vmwrite64(VMCS_GUEST_IA32_SYSENTER_CS, state.ia32_sysenter_cs);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_IA32_SYSENTER_ESP, state.ia32_sysenter_esp);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_IA32_SYSENTER_EIP, state.ia32_sysenter_eip);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_IA32_PAT, state.ia32_pat);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_IA32_DEBUGCTL, state.ia32_debugctl);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the VPS state in the provided state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param state the state save to store the VPS state to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        [[nodiscard]] constexpr auto
        vps_to_state_save(tls_t &tls, intrinsic_t &intrinsic, loader::state_save_t &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            ret = this->ensure_this_vps_is_loaded(tls, intrinsic);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            if (tls.active_vpsid == m_id) {
                state.rax = intrinsic.tls_reg(syscall::TLS_OFFSET_RAX).get();
                state.rbx = intrinsic.tls_reg(syscall::TLS_OFFSET_RBX).get();
                state.rcx = intrinsic.tls_reg(syscall::TLS_OFFSET_RCX).get();
                state.rdx = intrinsic.tls_reg(syscall::TLS_OFFSET_RDX).get();
                state.rbp = intrinsic.tls_reg(syscall::TLS_OFFSET_RBP).get();
                state.rsi = intrinsic.tls_reg(syscall::TLS_OFFSET_RSI).get();
                state.rdi = intrinsic.tls_reg(syscall::TLS_OFFSET_RDI).get();
                state.r8 = intrinsic.tls_reg(syscall::TLS_OFFSET_R8).get();
                state.r9 = intrinsic.tls_reg(syscall::TLS_OFFSET_R9).get();
                state.r10 = intrinsic.tls_reg(syscall::TLS_OFFSET_R10).get();
                state.r11 = intrinsic.tls_reg(syscall::TLS_OFFSET_R11).get();
                state.r12 = intrinsic.tls_reg(syscall::TLS_OFFSET_R12).get();
                state.r13 = intrinsic.tls_reg(syscall::TLS_OFFSET_R13).get();
                state.r14 = intrinsic.tls_reg(syscall::TLS_OFFSET_R14).get();
                state.r15 = intrinsic.tls_reg(syscall::TLS_OFFSET_R15).get();
            }
            else {
                state.rax = m_gprs.rax;
                state.rbx = m_gprs.rbx;
                state.rcx = m_gprs.rcx;
                state.rdx = m_gprs.rdx;
                state.rbp = m_gprs.rbp;
                state.rsi = m_gprs.rsi;
                state.rdi = m_gprs.rdi;
                state.r8 = m_gprs.r8;
                state.r9 = m_gprs.r9;
                state.r10 = m_gprs.r10;
                state.r11 = m_gprs.r11;
                state.r12 = m_gprs.r12;
                state.r13 = m_gprs.r13;
                state.r14 = m_gprs.r14;
                state.r15 = m_gprs.r15;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_RSP, &state.rsp);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_RIP, &state.rip);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_RFLAGS, &state.rflags);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread16(VMCS_GUEST_GDTR_LIMIT, &state.gdtr.limit);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            bsl::safe_uint64 gdtr_base{};
            ret = intrinsic.vmread64(VMCS_GUEST_GDTR_BASE, gdtr_base.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            state.gdtr.base = bsl::to_ptr<bsl::uint64 *>(gdtr_base);

            ret = intrinsic.vmread16(VMCS_GUEST_IDTR_LIMIT, &state.idtr.limit);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            bsl::safe_uint64 idtr_base{};
            ret = intrinsic.vmread64(VMCS_GUEST_IDTR_BASE, idtr_base.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            state.idtr.base = bsl::to_ptr<bsl::uint64 *>(idtr_base);

            ret = this->get_es_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->get_cs_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->get_ss_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->get_ds_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->get_fs_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->get_gs_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->get_ldtr_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = this->get_tr_segment_descriptor(intrinsic, state);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_CR0, &state.cr0);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            state.cr2 = m_vmcs_missing_registers.cr2;

            ret = intrinsic.vmread64(VMCS_GUEST_CR3, &state.cr3);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_CR4, &state.cr4);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            state.dr6 = m_vmcs_missing_registers.dr6;

            ret = intrinsic.vmread64(VMCS_GUEST_DR7, &state.dr7);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_IA32_EFER, &state.ia32_efer);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            state.ia32_star = m_vmcs_missing_registers.guest_ia32_star;
            state.ia32_lstar = m_vmcs_missing_registers.guest_ia32_lstar;
            state.ia32_cstar = m_vmcs_missing_registers.guest_ia32_cstar;
            state.ia32_fmask = m_vmcs_missing_registers.guest_ia32_fmask;

            ret = intrinsic.vmread64(VMCS_GUEST_FS_BASE, &state.ia32_fs_base);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_GS_BASE, &state.ia32_gs_base);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            state.ia32_kernel_gs_base = m_vmcs_missing_registers.guest_ia32_kernel_gs_base;

            ret = intrinsic.vmread64(VMCS_GUEST_IA32_SYSENTER_CS, &state.ia32_sysenter_cs);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_IA32_SYSENTER_ESP, &state.ia32_sysenter_esp);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_IA32_SYSENTER_EIP, &state.ia32_sysenter_eip);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_IA32_PAT, &state.ia32_pat);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_IA32_DEBUGCTL, &state.ia32_debugctl);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Reads a field from the VPS given the index of
        ///     the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FIELD_TYPE the type (i.e., size) of field to read
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param index the index of the field to read from the VPS
        ///   @return Returns the value of the requested field from the
        ///     VPS or bsl::safe_integral<FIELD_TYPE>::failure()
        ///
        template<typename FIELD_TYPE>
        [[nodiscard]] constexpr auto
        read(tls_t &tls, intrinsic_t &intrinsic, bsl::safe_uintmax const &index) noexcept
            -> bsl::safe_integral<FIELD_TYPE>
        {
            /// TODO:
            /// - Implement a field type checker to make sure the user is
            ///   using the proper field type here. Make sure that this field
            ///   type checker is only turned on with debug builds.
            ///

            bsl::errc_type ret{};
            bsl::safe_integral<FIELD_TYPE> val{};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::safe_integral<FIELD_TYPE>::failure();
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::safe_integral<FIELD_TYPE>::failure();
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_integral<FIELD_TYPE>::failure();
            }

            ret = this->ensure_this_vps_is_loaded(tls, intrinsic);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_integral<FIELD_TYPE>::failure();
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint16>::value) {
                ret = intrinsic.vmread16(index, val.data());
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return val;
                }

                return val;
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint32>::value) {
                ret = intrinsic.vmread32(index, val.data());
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return val;
                }

                return val;
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint64>::value) {
                ret = intrinsic.vmread64(index, val.data());
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return val;
                }

                return val;
            }

            bsl::error() << "unsupported field type\n" << bsl::here();
            return bsl::safe_integral<FIELD_TYPE>::failure();
        }

        /// <!-- description -->
        ///   @brief Writes a field to the VPS given the index of
        ///     the field and the value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FIELD_TYPE the type (i.e., size) of field to write
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param index the index of the field to write to the VPS
        ///   @param val the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///
        template<typename FIELD_TYPE>
        [[nodiscard]] constexpr auto
        write(
            tls_t &tls,
            intrinsic_t &intrinsic,
            bsl::safe_uintmax const &index,
            bsl::safe_integral<FIELD_TYPE> const &val) noexcept -> bsl::errc_type
        {
            /// TODO:
            /// - Implement a field type checker to make sure the user is
            ///   using the proper field type here. Make sure that this field
            ///   type checker is only turned on with debug builds.
            ///

            bsl::errc_type ret{};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!val)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            ret = this->ensure_this_vps_is_loaded(tls, intrinsic);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            constexpr auto vmcs_pinbased_ctls_idx{0x4000_umax};
            constexpr auto vmcs_exit_ctls_idx{0x400C_umax};
            constexpr auto vmcs_entry_ctls_idx{0x4012_umax};

            bsl::safe_integral<FIELD_TYPE> sanitized{val};

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint32>::value) {
                switch (index.get()) {
                    case vmcs_pinbased_ctls_idx.get(): {
                        constexpr auto vmcs_pinbased_ctls_mask{0x28_u32};
                        sanitized |= vmcs_pinbased_ctls_mask;
                        break;
                    }

                    case vmcs_exit_ctls_idx.get(): {
                        constexpr auto vmcs_exit_ctls_mask{0x3C0204_u32};
                        sanitized |= vmcs_exit_ctls_mask;
                        break;
                    }

                    case vmcs_entry_ctls_idx.get(): {
                        constexpr auto vmcs_entry_ctls_mask{0xC204_u32};
                        sanitized |= vmcs_entry_ctls_mask;
                        break;
                    }

                    default: {
                        break;
                    }
                }
            }
            else {
                switch (index.get()) {
                    case vmcs_pinbased_ctls_idx.get(): {
                        bsl::error() << "invalid integer type for field "    // --
                                     << bsl::hex(index)                      // --
                                     << bsl::endl                            // --
                                     << bsl::here();                         // --

                        return bsl::errc_failure;
                    }

                    case vmcs_exit_ctls_idx.get(): {
                        bsl::error() << "invalid integer type for field "    // --
                                     << bsl::hex(index)                      // --
                                     << bsl::endl                            // --
                                     << bsl::here();                         // --

                        return bsl::errc_failure;
                    }

                    case vmcs_entry_ctls_idx.get(): {
                        bsl::error() << "invalid integer type for field "    // --
                                     << bsl::hex(index)                      // --
                                     << bsl::endl                            // --
                                     << bsl::here();                         // --

                        return bsl::errc_failure;
                    }

                    default: {
                        break;
                    }
                }
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint16>::value) {
                ret = intrinsic.vmwrite16(index, sanitized);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint32>::value) {
                ret = intrinsic.vmwrite32(index, sanitized);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint64>::value) {
                ret = intrinsic.vmwrite64(index, sanitized);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            bsl::error() << "unsupported field type\n" << bsl::here();
            return bsl::errc_failure;
        }

        /// <!-- description -->
        ///   @brief Reads a field from the VPS given a bf_reg_t
        ///     defining the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param reg a bf_reg_t defining the field to read from the VPS
        ///   @return Returns the value of the requested field from the
        ///     VPS or bsl::safe_uintmax::failure() on failure.
        [[nodiscard]] constexpr auto
        read_reg(tls_t &tls, intrinsic_t &intrinsic, syscall::bf_reg_t const reg) noexcept
            -> bsl::safe_uintmax
        {
            bsl::safe_uint64 index{bsl::safe_uint64::failure()};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_uintmax::failure();
            }

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_rax: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RAX);
                    }

                    return m_gprs.rax;
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RBX);
                    }

                    return m_gprs.rbx;
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RCX);
                    }

                    return m_gprs.rcx;
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RDX);
                    }

                    return m_gprs.rdx;
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RBP);
                    }

                    return m_gprs.rbp;
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RSI);
                    }

                    return m_gprs.rsi;
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RDI);
                    }

                    return m_gprs.rdi;
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R8);
                    }

                    return m_gprs.r8;
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R9);
                    }

                    return m_gprs.r9;
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R10);
                    }

                    return m_gprs.r10;
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R11);
                    }

                    return m_gprs.r11;
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R12);
                    }

                    return m_gprs.r12;
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R13);
                    }

                    return m_gprs.r13;
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R14);
                    }

                    return m_gprs.r14;
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    if (tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R15);
                    }

                    return m_gprs.r15;
                }

                case syscall::bf_reg_t::bf_reg_t_rip: {
                    index = VMCS_GUEST_RIP;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rsp: {
                    index = VMCS_GUEST_RSP;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rflags: {
                    index = VMCS_GUEST_RFLAGS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_base_addr: {
                    index = VMCS_GUEST_GDTR_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_limit: {
                    index = VMCS_GUEST_GDTR_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_base_addr: {
                    index = VMCS_GUEST_IDTR_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_limit: {
                    index = VMCS_GUEST_IDTR_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es: {
                    index = VMCS_GUEST_ES_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_base_addr: {
                    index = VMCS_GUEST_ES_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_limit: {
                    index = VMCS_GUEST_ES_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_attributes: {
                    index = VMCS_GUEST_ES_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs: {
                    index = VMCS_GUEST_CS_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_base_addr: {
                    index = VMCS_GUEST_CS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_limit: {
                    index = VMCS_GUEST_CS_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_attributes: {
                    index = VMCS_GUEST_CS_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss: {
                    index = VMCS_GUEST_SS_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_base_addr: {
                    index = VMCS_GUEST_SS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_limit: {
                    index = VMCS_GUEST_SS_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_attributes: {
                    index = VMCS_GUEST_SS_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds: {
                    index = VMCS_GUEST_DS_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_base_addr: {
                    index = VMCS_GUEST_DS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_limit: {
                    index = VMCS_GUEST_DS_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_attributes: {
                    index = VMCS_GUEST_DS_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs: {
                    index = VMCS_GUEST_FS_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_base_addr: {
                    index = VMCS_GUEST_FS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_limit: {
                    index = VMCS_GUEST_FS_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_attributes: {
                    index = VMCS_GUEST_FS_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs: {
                    index = VMCS_GUEST_GS_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_base_addr: {
                    index = VMCS_GUEST_GS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_limit: {
                    index = VMCS_GUEST_GS_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_attributes: {
                    index = VMCS_GUEST_GS_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr: {
                    index = VMCS_GUEST_LDTR_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_base_addr: {
                    index = VMCS_GUEST_LDTR_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_limit: {
                    index = VMCS_GUEST_LDTR_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_attributes: {
                    index = VMCS_GUEST_LDTR_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr: {
                    index = VMCS_GUEST_TR_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_base_addr: {
                    index = VMCS_GUEST_TR_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_limit: {
                    index = VMCS_GUEST_TR_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_attributes: {
                    index = VMCS_GUEST_TR_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0: {
                    index = VMCS_GUEST_CR0;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr2: {
                    return m_vmcs_missing_registers.cr2;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3: {
                    index = VMCS_GUEST_CR3;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4: {
                    index = VMCS_GUEST_CR4;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_dr6: {
                    return m_vmcs_missing_registers.dr6;
                }

                case syscall::bf_reg_t::bf_reg_t_dr7: {
                    index = VMCS_GUEST_DR7;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_efer: {
                    index = VMCS_GUEST_IA32_EFER;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_star: {
                    return m_vmcs_missing_registers.guest_ia32_star;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_lstar: {
                    return m_vmcs_missing_registers.guest_ia32_lstar;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_cstar: {
                    return m_vmcs_missing_registers.guest_ia32_cstar;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_fmask: {
                    return m_vmcs_missing_registers.guest_ia32_fmask;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_fs_base: {
                    index = VMCS_GUEST_FS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_gs_base: {
                    index = VMCS_GUEST_GS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_kernel_gs_base: {
                    return m_vmcs_missing_registers.guest_ia32_kernel_gs_base;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_sysenter_cs: {
                    index = VMCS_GUEST_IA32_SYSENTER_CS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_sysenter_esp: {
                    index = VMCS_GUEST_IA32_SYSENTER_ESP;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_sysenter_eip: {
                    index = VMCS_GUEST_IA32_SYSENTER_EIP;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_pat: {
                    index = VMCS_GUEST_IA32_PAT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_debugctl: {
                    index = VMCS_GUEST_IA32_DEBUGCTL;
                    break;
                }

                default: {
                    bsl::error() << "unknown by bf_reg_t\n" << bsl::here();
                    break;
                }
            }

            auto const val{this->read<bsl::uint64>(tls, intrinsic, index)};
            if (bsl::unlikely(!val)) {
                bsl::print<bsl::V>() << bsl::here();
                return val;
            }

            return val;
        }

        /// <!-- description -->
        ///   @brief Writes a field to the VPS given a bf_reg_t
        ///     defining the field and a value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param reg a bf_reg_t defining the field to write to the VPS
        ///   @param val the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///
        [[nodiscard]] constexpr auto
        write_reg(
            tls_t &tls,
            intrinsic_t &intrinsic,
            syscall::bf_reg_t const reg,
            bsl::safe_uintmax const &val) noexcept -> bsl::errc_type
        {
            bsl::safe_uint64 index{bsl::safe_uint64::failure()};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(!val)) {
                bsl::error() << "invalid value\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_rax: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, val);
                    }
                    else {
                        m_gprs.rax = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, val);
                    }
                    else {
                        m_gprs.rbx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, val);
                    }
                    else {
                        m_gprs.rcx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, val);
                    }
                    else {
                        m_gprs.rdx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, val);
                    }
                    else {
                        m_gprs.rbp = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, val);
                    }
                    else {
                        m_gprs.rsi = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, val);
                    }
                    else {
                        m_gprs.rdi = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, val);
                    }
                    else {
                        m_gprs.r8 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, val);
                    }
                    else {
                        m_gprs.r9 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, val);
                    }
                    else {
                        m_gprs.r10 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, val);
                    }
                    else {
                        m_gprs.r11 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, val);
                    }
                    else {
                        m_gprs.r12 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, val);
                    }
                    else {
                        m_gprs.r13 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, val);
                    }
                    else {
                        m_gprs.r14 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    if (tls.active_vpsid == m_id) {
                        intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, val);
                    }
                    else {
                        m_gprs.r15 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rip: {
                    index = VMCS_GUEST_RIP;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rsp: {
                    index = VMCS_GUEST_RSP;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rflags: {
                    index = VMCS_GUEST_RFLAGS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_base_addr: {
                    index = VMCS_GUEST_GDTR_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_limit: {
                    index = VMCS_GUEST_GDTR_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_base_addr: {
                    index = VMCS_GUEST_IDTR_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_limit: {
                    index = VMCS_GUEST_IDTR_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es: {
                    index = VMCS_GUEST_ES_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_base_addr: {
                    index = VMCS_GUEST_ES_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_limit: {
                    index = VMCS_GUEST_ES_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_attributes: {
                    index = VMCS_GUEST_ES_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs: {
                    index = VMCS_GUEST_CS_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_base_addr: {
                    index = VMCS_GUEST_CS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_limit: {
                    index = VMCS_GUEST_CS_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_attributes: {
                    index = VMCS_GUEST_CS_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss: {
                    index = VMCS_GUEST_SS_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_base_addr: {
                    index = VMCS_GUEST_SS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_limit: {
                    index = VMCS_GUEST_SS_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_attributes: {
                    index = VMCS_GUEST_SS_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds: {
                    index = VMCS_GUEST_DS_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_base_addr: {
                    index = VMCS_GUEST_DS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_limit: {
                    index = VMCS_GUEST_DS_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_attributes: {
                    index = VMCS_GUEST_DS_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs: {
                    index = VMCS_GUEST_FS_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_base_addr: {
                    index = VMCS_GUEST_FS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_limit: {
                    index = VMCS_GUEST_FS_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_attributes: {
                    index = VMCS_GUEST_FS_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs: {
                    index = VMCS_GUEST_GS_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_base_addr: {
                    index = VMCS_GUEST_GS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_limit: {
                    index = VMCS_GUEST_GS_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_attributes: {
                    index = VMCS_GUEST_GS_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr: {
                    index = VMCS_GUEST_LDTR_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_base_addr: {
                    index = VMCS_GUEST_LDTR_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_limit: {
                    index = VMCS_GUEST_LDTR_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_attributes: {
                    index = VMCS_GUEST_LDTR_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr: {
                    index = VMCS_GUEST_TR_SELECTOR;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_base_addr: {
                    index = VMCS_GUEST_TR_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_limit: {
                    index = VMCS_GUEST_TR_LIMIT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_attributes: {
                    index = VMCS_GUEST_TR_ACCESS_RIGHTS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0: {
                    index = VMCS_GUEST_CR0;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr2: {
                    m_vmcs_missing_registers.cr2 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3: {
                    index = VMCS_GUEST_CR3;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4: {
                    index = VMCS_GUEST_CR4;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_dr6: {
                    m_vmcs_missing_registers.dr6 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr7: {
                    index = VMCS_GUEST_DR7;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_efer: {
                    index = VMCS_GUEST_IA32_EFER;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_star: {
                    m_vmcs_missing_registers.guest_ia32_star = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_lstar: {
                    m_vmcs_missing_registers.guest_ia32_lstar = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_cstar: {
                    m_vmcs_missing_registers.guest_ia32_cstar = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_fmask: {
                    m_vmcs_missing_registers.guest_ia32_fmask = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_fs_base: {
                    index = VMCS_GUEST_FS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_gs_base: {
                    index = VMCS_GUEST_GS_BASE;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_kernel_gs_base: {
                    m_vmcs_missing_registers.guest_ia32_kernel_gs_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_sysenter_cs: {
                    index = VMCS_GUEST_IA32_SYSENTER_CS;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_sysenter_esp: {
                    index = VMCS_GUEST_IA32_SYSENTER_ESP;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_sysenter_eip: {
                    index = VMCS_GUEST_IA32_SYSENTER_EIP;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_pat: {
                    index = VMCS_GUEST_IA32_PAT;
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ia32_debugctl: {
                    index = VMCS_GUEST_IA32_DEBUGCTL;
                    break;
                }

                default: {
                    bsl::error() << "unknown by bf_reg_t\n" << bsl::here();
                    break;
                }
            }

            auto const ret{this->write<bsl::uint64>(tls, intrinsic, index, val)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return ret;
        }

        /// <!-- description -->
        ///   @brief Runs the VPS. Note that this function does not
        ///     return until a VMExit occurs. Once complete, this function
        ///     will return the VMExit reason.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param log the VMExit log to use
        ///   @return Returns the VMExit reason on success, or
        ///
        [[nodiscard]] constexpr auto
        run(tls_t &tls, intrinsic_t &intrinsic, vmexit_log_t &log) noexcept -> bsl::safe_uintmax
        {
            bsl::errc_type ret{};
            constexpr auto invalid_exit_reason{0xFFFFFFFF00000000_umax};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely_assert(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::safe_uintmax::failure();
            }

            if (bsl::unlikely_assert(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                        // --
                             << bsl::hex(m_id)               // --
                             << " is assigned to pp "        // --
                             << bsl::hex(m_assigned_ppid)    // --
                             << " and cannot run by pp "     // --
                             << bsl::hex(tls.ppid)           // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::safe_uintmax::failure();
            }

            ret = this->ensure_this_vps_is_loaded(tls, intrinsic);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            bsl::safe_uintmax const exit_reason{intrinsic_vmrun(&m_vmcs_missing_registers)};
            if (bsl::unlikely(exit_reason > invalid_exit_reason)) {
                bsl::error() << "vmlaunch/vmresume failed with error code "    // --
                             << (exit_reason & (~invalid_exit_reason))         // --
                             << bsl::endl                                      // --
                             << bsl::here();                                   // --

                return bsl::safe_uintmax::failure();
            }

            if constexpr (!(BSL_DEBUG_LEVEL < bsl::VV)) {
                log.add(
                    tls.ppid,
                    {tls.active_vmid,
                     tls.active_vpid,
                     tls.active_vpsid,
                     exit_reason,
                     intrinsic.vmread64_quiet(VMCS_EXIT_QUALIFICATION),
                     intrinsic.vmread64_quiet(VMCS_VMEXIT_INSTRUCTION_INFORMATION),
                     {},
                     intrinsic.tls_reg(syscall::TLS_OFFSET_RAX),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_RBX),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_RCX),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_RDX),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_RBP),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_RSI),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_RDI),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_R8),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_R9),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_R10),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_R11),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_R12),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_R13),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_R14),
                     intrinsic.tls_reg(syscall::TLS_OFFSET_R15),
                     intrinsic.vmread64_quiet(VMCS_GUEST_RSP),
                     intrinsic.vmread64_quiet(VMCS_GUEST_RIP)});
            }

            /// TODO:
            /// - Add check logic to if an entry failure occurs and output
            ///   what the error was and why.
            ///

            return exit_reason;
        }

        /// <!-- description -->
        ///   @brief Advance the IP of the VPS
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        advance_ip(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint64 rip{};
            bsl::safe_uint64 len{};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            ret = this->ensure_this_vps_is_loaded(tls, intrinsic);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_GUEST_RIP, rip.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmread64(VMCS_VMEXIT_INSTRUCTION_LENGTH, len.data());
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmwrite64(VMCS_GUEST_RIP, rip + len);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return ret;
        }

        /// <!-- description -->
        ///   @brief Clears the VPS's internal cache. Note that this is a
        ///     hardware specific function and doesn't change the actual
        ///     values stored in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        clear(tls_t &tls, intrinsic_t &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::unlikely_assert(!m_id)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_precondition;
            }

            if (bsl::unlikely(m_allocated != allocated_status_t::allocated)) {
                bsl::error() << "vps "                                             // --
                             << bsl::hex(m_id)                                     // --
                             << "'s status is not allocated and cannot be used"    // --
                             << bsl::endl                                          // --
                             << bsl::here();                                       // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(tls.ppid)                     // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            ret = this->ensure_this_vps_is_loaded(tls, intrinsic);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmclear(&m_vmcs_phys);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            ret = intrinsic.vmload(&m_vmcs_phys);
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            tls.loaded_vpsid = m_id.get();
            m_vmcs_missing_registers.launched = {};

            return ret;
        }

        /// <!-- description -->
        ///   @brief Dumps the vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///
        constexpr void
        dump(tls_t &tls, intrinsic_t &intrinsic) const noexcept
        {
            bsl::discard(tls);

            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            // clang-format off

            if (bsl::unlikely(!m_id)) {
                bsl::print() << "[error]" << bsl::endl;
                return;
            }

            bsl::print() << bsl::mag << "vps [";
            bsl::print() << bsl::rst << bsl::hex(m_id);
            bsl::print() << bsl::mag << "] dump: ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Header
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^40s", "description "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::cyn << bsl::fmt{"^19s", "value "};
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            /// Allocated
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<40s", "allocated "};
            bsl::print() << bsl::ylw << "| ";
            if (this->is_allocated()) {
                bsl::print() << bsl::grn << bsl::fmt{"^19s", "yes "};
            }
            else {
                bsl::print() << bsl::red << bsl::fmt{"^19s", "no "};
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Assigned VP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<40s", "assigned vp "};
            bsl::print() << bsl::ylw << "| ";
            if (m_assigned_vpid != syscall::BF_INVALID_ID) {
                bsl::print() << bsl::grn << "      " << bsl::hex(m_assigned_vpid) << "       ";
            }
            else {
                bsl::print() << bsl::red << "      " << bsl::hex(m_assigned_vpid) << "       ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Assigned PP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<40s", "assigned pp "};
            bsl::print() << bsl::ylw << "| ";
            if (m_assigned_ppid != syscall::BF_INVALID_ID) {
                bsl::print() << bsl::grn << "      " << bsl::hex(m_assigned_ppid) << "       ";
            }
            else {
                bsl::print() << bsl::red << "      " << bsl::hex(m_assigned_ppid) << "       ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Guest Missing Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            if (!this->is_allocated()) {
                return;
            }

            if (tls.active_vpsid == m_id) {
                this->dump("rax ", intrinsic.tls_reg(syscall::TLS_OFFSET_RAX));
                this->dump("rbx ", intrinsic.tls_reg(syscall::TLS_OFFSET_RBX));
                this->dump("rcx ", intrinsic.tls_reg(syscall::TLS_OFFSET_RCX));
                this->dump("rdx ", intrinsic.tls_reg(syscall::TLS_OFFSET_RDX));
                this->dump("rbp ", intrinsic.tls_reg(syscall::TLS_OFFSET_RBP));
                this->dump("rsi ", intrinsic.tls_reg(syscall::TLS_OFFSET_RSI));
                this->dump("rdi ", intrinsic.tls_reg(syscall::TLS_OFFSET_RDI));
                this->dump("r8 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R8));
                this->dump("r9 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R9));
                this->dump("r10 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R10));
                this->dump("r11 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R11));
                this->dump("r12 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R12));
                this->dump("r13 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R13));
                this->dump("r14 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R14));
                this->dump("r15 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R15));
            }
            else {
                this->dump("rax ", bsl::make_safe(m_gprs.rax));
                this->dump("rbx ", bsl::make_safe(m_gprs.rbx));
                this->dump("rcx ", bsl::make_safe(m_gprs.rcx));
                this->dump("rdx ", bsl::make_safe(m_gprs.rdx));
                this->dump("rbp ", bsl::make_safe(m_gprs.rbp));
                this->dump("rsi ", bsl::make_safe(m_gprs.rsi));
                this->dump("rdi ", bsl::make_safe(m_gprs.rdi));
                this->dump("r8 ", bsl::make_safe(m_gprs.r8));
                this->dump("r9 ", bsl::make_safe(m_gprs.r9));
                this->dump("r10 ", bsl::make_safe(m_gprs.r10));
                this->dump("r11 ", bsl::make_safe(m_gprs.r11));
                this->dump("r12 ", bsl::make_safe(m_gprs.r12));
                this->dump("r13 ", bsl::make_safe(m_gprs.r13));
                this->dump("r14 ", bsl::make_safe(m_gprs.r14));
                this->dump("r15 ", bsl::make_safe(m_gprs.r15));
            }

            /// 16 Bit Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("virtual_processor_identifier ", intrinsic.vmread16_quiet(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER));
            this->dump("posted_interrupt_notification_vector ", intrinsic.vmread16_quiet(VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR));
            this->dump("eptp_index ", intrinsic.vmread16_quiet(VMCS_EPTP_INDEX));

            /// 16 Bit Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("es_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_ES_SELECTOR));
            this->dump("cs_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_CS_SELECTOR));
            this->dump("ss_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_SS_SELECTOR));
            this->dump("ds_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_DS_SELECTOR));
            this->dump("fs_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_FS_SELECTOR));
            this->dump("gs_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_GS_SELECTOR));
            this->dump("ldtr_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_LDTR_SELECTOR));
            this->dump("tr_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_TR_SELECTOR));
            this->dump("interrupt_status ", intrinsic.vmread16_quiet(VMCS_GUEST_INTERRUPT_STATUS));
            this->dump("pml_index ", intrinsic.vmread16_quiet(VMCS_PML_INDEX));

            /// 64 Bit Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("address_of_io_bitmap_a ", intrinsic.vmread64_quiet(VMCS_ADDRESS_OF_IO_BITMAP_A));
            this->dump("address_of_io_bitmap_b ", intrinsic.vmread64_quiet(VMCS_ADDRESS_OF_IO_BITMAP_B));
            this->dump("address_of_msr_bitmaps ", intrinsic.vmread64_quiet(VMCS_ADDRESS_OF_MSR_BITMAPS));
            this->dump("vmexit_msr_store_address ", intrinsic.vmread64_quiet(VMCS_VMEXIT_MSR_STORE_ADDRESS));
            this->dump("vmexit_msr_load_address ", intrinsic.vmread64_quiet(VMCS_VMEXIT_MSR_LOAD_ADDRESS));
            this->dump("vmentry_msr_load_address ", intrinsic.vmread64_quiet(VMCS_VMENTRY_MSR_LOAD_ADDRESS));
            this->dump("executive_vmcs_pointer ", intrinsic.vmread64_quiet(VMCS_EXECUTIVE_VMCS_POINTER));
            this->dump("pml_address ", intrinsic.vmread64_quiet(VMCS_PML_ADDRESS));
            this->dump("tsc_offset ", intrinsic.vmread64_quiet(VMCS_TSC_OFFSET));
            this->dump("virtual_apic_address ", intrinsic.vmread64_quiet(VMCS_VIRTUAL_APIC_ADDRESS));
            this->dump("apic_access_address ", intrinsic.vmread64_quiet(VMCS_APIC_ACCESS_ADDRESS));
            this->dump("posted_interrupt_descriptor_address ", intrinsic.vmread64_quiet(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS));
            this->dump("vm_function_controls ", intrinsic.vmread64_quiet(VMCS_VM_FUNCTION_CONTROLS));
            this->dump("ept_pointer ", intrinsic.vmread64_quiet(VMCS_EPT_POINTER));
            this->dump("eoi_exit_bitmap0 ", intrinsic.vmread64_quiet(VMCS_EOI_EXIT_BITMAP0));
            this->dump("eoi_exit_bitmap1 ", intrinsic.vmread64_quiet(VMCS_EOI_EXIT_BITMAP1));
            this->dump("eoi_exit_bitmap2 ", intrinsic.vmread64_quiet(VMCS_EOI_EXIT_BITMAP2));
            this->dump("eoi_exit_bitmap3 ", intrinsic.vmread64_quiet(VMCS_EOI_EXIT_BITMAP3));
            this->dump("eptp_list_address ", intrinsic.vmread64_quiet(VMCS_EPTP_LIST_ADDRESS));
            this->dump("vmread_bitmap_address ", intrinsic.vmread64_quiet(VMCS_VMREAD_BITMAP_ADDRESS));
            this->dump("vmwrite_bitmap_address ", intrinsic.vmread64_quiet(VMCS_VMWRITE_BITMAP_ADDRESS));
            this->dump("virt_exception_information_address ", intrinsic.vmread64_quiet(VMCS_VIRT_EXCEPTION_INFORMATION_ADDRESS));
            this->dump("xss_exiting_bitmap ", intrinsic.vmread64_quiet(VMCS_XSS_EXITING_BITMAP));
            this->dump("encls_exiting_bitmap ", intrinsic.vmread64_quiet(VMCS_ENCLS_EXITING_BITMAP));
            this->dump("sub_page_permission_table_pointer ", intrinsic.vmread64_quiet(VMCS_SUB_PAGE_PERMISSION_TABLE_POINTER));
            this->dump("tls_multiplier ", intrinsic.vmread64_quiet(VMCS_TLS_MULTIPLIER));

            /// 64 Bit Read-Only Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("guest_physical_address ", intrinsic.vmread64_quiet(VMCS_GUEST_PHYSICAL_ADDRESS));

            /// 64 Bit Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("vmcs_link_pointer ", intrinsic.vmread64_quiet(VMCS_VMCS_LINK_POINTER));
            this->dump("ia32_debugctl ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_DEBUGCTL));
            this->dump("ia32_pat ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_PAT));
            this->dump("ia32_efer ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_EFER));
            this->dump("ia32_perf_global_ctrl ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL));
            this->dump("guest_pdpte0 ", intrinsic.vmread64_quiet(VMCS_GUEST_PDPTE0));
            this->dump("guest_pdpte1 ", intrinsic.vmread64_quiet(VMCS_GUEST_PDPTE1));
            this->dump("guest_pdpte2 ", intrinsic.vmread64_quiet(VMCS_GUEST_PDPTE2));
            this->dump("guest_pdpte3 ", intrinsic.vmread64_quiet(VMCS_GUEST_PDPTE3));
            this->dump("ia32_bndcfgs ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_BNDCFGS));
            this->dump("guest_rtit_ctl ", intrinsic.vmread64_quiet(VMCS_GUEST_RTIT_CTL));
            this->dump("ia32_star ", bsl::make_safe(m_vmcs_missing_registers.guest_ia32_star));
            this->dump("ia32_lstar ", bsl::make_safe(m_vmcs_missing_registers.guest_ia32_lstar));
            this->dump("ia32_cstar ", bsl::make_safe(m_vmcs_missing_registers.guest_ia32_cstar));
            this->dump("ia32_fmask ", bsl::make_safe(m_vmcs_missing_registers.guest_ia32_fmask));
            this->dump("ia32_kernel_gs_base ", bsl::make_safe(m_vmcs_missing_registers.guest_ia32_kernel_gs_base));

            /// 32 Bit Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("pin_based_vm_execution_ctls ", intrinsic.vmread32_quiet(VMCS_PIN_BASED_VM_EXECUTION_CTLS));
            this->dump("primary_proc_based_vm_execution_ctls ", intrinsic.vmread32_quiet(VMCS_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS));
            this->dump("exception_bitmap ", intrinsic.vmread32_quiet(VMCS_EXCEPTION_BITMAP));
            this->dump("page_fault_error_code_mask ", intrinsic.vmread32_quiet(VMCS_PAGE_FAULT_ERROR_CODE_MASK));
            this->dump("page_fault_error_code_match ", intrinsic.vmread32_quiet(VMCS_PAGE_FAULT_ERROR_CODE_MATCH));
            this->dump("cr3_target_count ", intrinsic.vmread32_quiet(VMCS_CR3_TARGET_COUNT));
            this->dump("vmexit_ctls ", intrinsic.vmread32_quiet(VMCS_VMEXIT_CTLS));
            this->dump("vmexit_msr_store_count ", intrinsic.vmread32_quiet(VMCS_VMEXIT_MSR_STORE_COUNT));
            this->dump("vmexit_msr_load_count ", intrinsic.vmread32_quiet(VMCS_VMEXIT_MSR_LOAD_COUNT));
            this->dump("vmentry_ctls ", intrinsic.vmread32_quiet(VMCS_VMENTRY_CTLS));
            this->dump("vmentry_msr_load_count ", intrinsic.vmread32_quiet(VMCS_VMENTRY_MSR_LOAD_COUNT));
            this->dump("vmentry_interrupt_information_field ", intrinsic.vmread32_quiet(VMCS_VMENTRY_INTERRUPT_INFORMATION_FIELD));
            this->dump("vmentry_exception_error_code ", intrinsic.vmread32_quiet(VMCS_VMENTRY_EXCEPTION_ERROR_CODE));
            this->dump("vmentry_instruction_length ", intrinsic.vmread32_quiet(VMCS_VMENTRY_INSTRUCTION_LENGTH));
            this->dump("tpr_threshold ", intrinsic.vmread32_quiet(VMCS_TPR_THRESHOLD));
            this->dump("secondary_proc_based_vm_execution_ctls ", intrinsic.vmread32_quiet(VMCS_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS));
            this->dump("ple_gap ", intrinsic.vmread32_quiet(VMCS_PLE_GAP));
            this->dump("ple_window ", intrinsic.vmread32_quiet(VMCS_PLE_WINDOW));

            /// 32 Bit Read-Only Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("exit_reason ", intrinsic.vmread32_quiet(VMCS_EXIT_REASON));
            this->dump("vmexit_interruption_information ", intrinsic.vmread32_quiet(VMCS_VMEXIT_INTERRUPTION_INFORMATION));
            this->dump("vmexit_interruption_error_code ", intrinsic.vmread32_quiet(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE));
            this->dump("idt_vectoring_information_field ", intrinsic.vmread32_quiet(VMCS_IDT_VECTORING_INFORMATION_FIELD));
            this->dump("idt_vectoring_error_code ", intrinsic.vmread32_quiet(VMCS_IDT_VECTORING_ERROR_CODE));
            this->dump("vmexit_instruction_length ", intrinsic.vmread32_quiet(VMCS_VMEXIT_INSTRUCTION_LENGTH));
            this->dump("vmexit_instruction_information ", intrinsic.vmread32_quiet(VMCS_VMEXIT_INSTRUCTION_INFORMATION));

            /// 32 Bit Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("es_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_ES_LIMIT));
            this->dump("cs_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_CS_LIMIT));
            this->dump("ss_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_SS_LIMIT));
            this->dump("ds_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_DS_LIMIT));
            this->dump("fs_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_FS_LIMIT));
            this->dump("gs_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_GS_LIMIT));
            this->dump("ldtr_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_LDTR_LIMIT));
            this->dump("tr_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_TR_LIMIT));
            this->dump("gdtr_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_GDTR_LIMIT));
            this->dump("idtr_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_IDTR_LIMIT));
            this->dump("es_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_ES_ACCESS_RIGHTS));
            this->dump("cs_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_CS_ACCESS_RIGHTS));
            this->dump("ss_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_SS_ACCESS_RIGHTS));
            this->dump("ds_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_DS_ACCESS_RIGHTS));
            this->dump("fs_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_FS_ACCESS_RIGHTS));
            this->dump("gs_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_GS_ACCESS_RIGHTS));
            this->dump("ldtr_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_LDTR_ACCESS_RIGHTS));
            this->dump("tr_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_TR_ACCESS_RIGHTS));
            this->dump("guest_interruptibility_state ", intrinsic.vmread32_quiet(VMCS_GUEST_INTERRUPTIBILITY_STATE));
            this->dump("guest_activity_state ", intrinsic.vmread32_quiet(VMCS_GUEST_ACTIVITY_STATE));
            this->dump("guest_smbase ", intrinsic.vmread32_quiet(VMCS_GUEST_SMBASE));
            this->dump("ia32_sysenter_cs ", intrinsic.vmread32_quiet(VMCS_GUEST_IA32_SYSENTER_CS));
            this->dump("vmx_preemption_timer_value ", intrinsic.vmread32_quiet(VMCS_VMX_PREEMPTION_TIMER_VALUE));

            /// Natural-Width Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("cr0_guest_host_mask ", intrinsic.vmread64_quiet(VMCS_CR0_GUEST_HOST_MASK));
            this->dump("cr4_guest_host_mask ", intrinsic.vmread64_quiet(VMCS_CR4_GUEST_HOST_MASK));
            this->dump("cr0_read_shadow ", intrinsic.vmread64_quiet(VMCS_CR0_READ_SHADOW));
            this->dump("cr4_read_shadow ", intrinsic.vmread64_quiet(VMCS_CR4_READ_SHADOW));
            this->dump("cr3_target_value0 ", intrinsic.vmread64_quiet(VMCS_CR3_TARGET_VALUE0));
            this->dump("cr3_target_value1 ", intrinsic.vmread64_quiet(VMCS_CR3_TARGET_VALUE1));
            this->dump("cr3_target_value2 ", intrinsic.vmread64_quiet(VMCS_CR3_TARGET_VALUE2));
            this->dump("cr3_target_value3 ", intrinsic.vmread64_quiet(VMCS_CR3_TARGET_VALUE3));

            /// Natural-Width Read-Only Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("exit_qualification ", intrinsic.vmread64_quiet(VMCS_EXIT_QUALIFICATION));
            this->dump("io_rcx ", intrinsic.vmread64_quiet(VMCS_IO_RCX));
            this->dump("io_rsi ", intrinsic.vmread64_quiet(VMCS_IO_RSI));
            this->dump("io_rdi ", intrinsic.vmread64_quiet(VMCS_IO_RDI));
            this->dump("io_rip ", intrinsic.vmread64_quiet(VMCS_IO_RIP));
            this->dump("guest_linear_address ", intrinsic.vmread64_quiet(VMCS_GUEST_LINEAR_ADDRESS));

            /// Natural-Width Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump("cr0 ", intrinsic.vmread64_quiet(VMCS_GUEST_CR0));
            this->dump("cr2 ", bsl::make_safe(m_vmcs_missing_registers.cr2));
            this->dump("cr3 ", intrinsic.vmread64_quiet(VMCS_GUEST_CR3));
            this->dump("cr4 ", intrinsic.vmread64_quiet(VMCS_GUEST_CR4));
            this->dump("es_base ", intrinsic.vmread64_quiet(VMCS_GUEST_ES_BASE));
            this->dump("cs_base ", intrinsic.vmread64_quiet(VMCS_GUEST_CS_BASE));
            this->dump("ss_base ", intrinsic.vmread64_quiet(VMCS_GUEST_SS_BASE));
            this->dump("ds_base ", intrinsic.vmread64_quiet(VMCS_GUEST_DS_BASE));
            this->dump("fs_base ", intrinsic.vmread64_quiet(VMCS_GUEST_FS_BASE));
            this->dump("gs_base ", intrinsic.vmread64_quiet(VMCS_GUEST_GS_BASE));
            this->dump("ldtr_base ", intrinsic.vmread64_quiet(VMCS_GUEST_LDTR_BASE));
            this->dump("tr_base ", intrinsic.vmread64_quiet(VMCS_GUEST_TR_BASE));
            this->dump("gdtr_base ", intrinsic.vmread64_quiet(VMCS_GUEST_GDTR_BASE));
            this->dump("idtr_base ", intrinsic.vmread64_quiet(VMCS_GUEST_IDTR_BASE));
            this->dump("dr6 ", bsl::make_safe(m_vmcs_missing_registers.dr6));
            this->dump("dr7 ", intrinsic.vmread64_quiet(VMCS_GUEST_DR7));
            this->dump("rsp ", intrinsic.vmread64_quiet(VMCS_GUEST_RSP));
            this->dump("rip ", intrinsic.vmread64_quiet(VMCS_GUEST_RIP));
            this->dump("rflags ", intrinsic.vmread64_quiet(VMCS_GUEST_RFLAGS));
            this->dump("guest_pending_debug_exceptions ", intrinsic.vmread64_quiet(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS));
            this->dump("ia32_sysenter_esp ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_SYSENTER_ESP));
            this->dump("ia32_sysenter_eip ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_SYSENTER_EIP));

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            // clang-format on
        }
    };
}

#endif
