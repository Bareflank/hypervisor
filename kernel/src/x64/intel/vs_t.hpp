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

#include <allocated_status_t.hpp>
#include <bf_constants.hpp>
#include <bf_reg_t.hpp>
#include <general_purpose_regs_t.hpp>
#include <intrinsic_t.hpp>
#include <missing_registers_t.hpp>
#include <page_pool_t.hpp>
#include <running_status_t.hpp>
#include <tls_t.hpp>
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

namespace mk
{
    /// @brief entry point prototype
    extern "C" void intrinsic_vmexit(void) noexcept;

    /// @brief defines the VMX_BASIC MSR
    constexpr auto MSR_VMX_BASIC{0x480_u32};
    /// @brief defines the PAT MSR
    constexpr auto MSR_PAT{0x277_u32};
    /// @brief defines the SYSENTER_CS MSR
    constexpr auto MSR_SYSENTER_CS{0x174_u32};
    /// @brief defines the SYSENTER_ESP MSR
    constexpr auto MSR_SYSENTER_ESP{0x175_u32};
    /// @brief defines the SYSENTER_EIP MSR
    constexpr auto MSR_SYSENTER_EIP{0x176_u32};
    /// @brief defines the EFER MSR
    constexpr auto MSR_EFER{0xC0000080_u32};
    /// @brief defines the STAR MSR
    constexpr auto MSR_STAR{0xC0000081_u32};
    /// @brief defines the LSTAR MSR
    constexpr auto MSR_LSTAR{0xC0000082_u32};
    /// @brief defines the CSTAR MSR
    constexpr auto MSR_CSTAR{0xC0000083_u32};
    /// @brief defines the FMASK MSR
    constexpr auto MSR_FMASK{0xC0000084_u32};
    /// @brief defines the FS_BASE MSR
    constexpr auto MSR_FS_BASE{0xC0000100_u32};
    /// @brief defines the GS_BASE MSR
    constexpr auto MSR_GS_BASE{0xC0000101_u32};
    /// @brief defines the KERNEL_GS_BASE MSR
    constexpr auto MSR_KERNEL_GS_BASE{0xC0000102_u32};
    /// @brief defines the MSR_VMX_CR0_FIXED0 MSR
    constexpr auto MSR_VMX_CR0_FIXED0{0x00000486_u32};
    /// @brief defines the MSR_VMX_CR0_FIXED1 MSR
    constexpr auto MSR_VMX_CR0_FIXED1{0x00000487_u32};
    /// @brief defines the MSR_VMX_CR4_FIXED0 MSR
    constexpr auto MSR_VMX_CR4_FIXED0{0x00000488_u32};
    /// @brief defines the MSR_VMX_CR4_FIXED1 MSR
    constexpr auto MSR_VMX_CR4_FIXED1{0x00000489_u32};
    /// @brief defines the MSR_VMX_TRUE_PIN_CTLS MSR
    constexpr auto MSR_VMX_TRUE_PIN_CTLS{0x0000048D_u32};
    /// @brief defines the MSR_VMX_TRUE_PROC_CTLS MSR
    constexpr auto MSR_VMX_TRUE_PROC_CTLS{0x0000048E_u32};
    /// @brief defines the MSR_VMX_TRUE_EXIT_CTLS MSR
    constexpr auto MSR_VMX_TRUE_EXIT_CTLS{0x0000048F_u32};
    /// @brief defines the MSR_VMX_TRUE_ENTRY_CTLS MSR
    constexpr auto MSR_VMX_TRUE_ENTRY_CTLS{0x00000490_u32};
    /// @brief defines the MSR_VMX_TRUE_PROC2_CTLS MSR
    constexpr auto MSR_VMX_TRUE_PROC2_CTLS{0x0000048B_u32};

    /// @class mk::vs_t
    ///
    /// <!-- description -->
    ///   @brief Defines the microkernel's notion of a VS.
    ///
    class vs_t final
    {
        /// @brief stores the ID associated with this vp_t
        bsl::safe_u16 m_id{};
        /// @brief stores whether or not this vp_t is allocated.
        allocated_status_t m_allocated{};
        /// @brief stores the status of the vs_t
        running_status_t m_status{};
        /// @brief stores the ID of the VM this vs_t is assigned to
        bsl::safe_u16 m_assigned_vmid{};
        /// @brief stores the ID of the VP this vs_t is assigned to
        bsl::safe_u16 m_assigned_vpid{};
        /// @brief stores the ID of the PP this vp_t is assigned to
        bsl::safe_u16 m_assigned_ppid{};
        /// @brief stores the ID of the PP this vp_t is active on
        bsl::safe_u16 m_active_ppid{};

        /// @brief stores a pointer to the guest vmcs being managed by this VS
        vmcs_t *m_vmcs{};
        /// @brief stores the physical address of the guest vmcs
        bsl::safe_umx m_vmcs_phys{};
        /// @brief stores the general purpose registers
        general_purpose_regs_t m_gprs{};
        /// @brief stores the rest of the state the vmcs doesn't
        missing_registers_t m_missing_registers{};

        /// @brief stores the CR0 fixed0 values for sanitization
        bsl::safe_u64 m_vmx_cr0_fixed0{};
        /// @brief stores the CR0 fixed1 values for sanitization
        bsl::safe_u64 m_vmx_cr0_fixed1{};
        /// @brief stores the CR4 fixed0 values for sanitization
        bsl::safe_u64 m_vmx_cr4_fixed0{};
        /// @brief stores the CR4 fixed1 values for sanitization
        bsl::safe_u64 m_vmx_cr4_fixed1{};

        /// @brief stores the pin ctls fixed0 values for sanitization
        bsl::safe_u64 m_vmx_pin_fixed0{};
        /// @brief stores the pin ctls fixed1 values for sanitization
        bsl::safe_u64 m_vmx_pin_fixed1{};
        /// @brief stores the proc ctls fixed0 values for sanitization
        bsl::safe_u64 m_vmx_proc_fixed0{};
        /// @brief stores the proc ctls fixed1 values for sanitization
        bsl::safe_u64 m_vmx_proc_fixed1{};
        /// @brief stores the exit ctls fixed0 values for sanitization
        bsl::safe_u64 m_vmx_exit_fixed0{};
        /// @brief stores the exit ctls fixed1 values for sanitization
        bsl::safe_u64 m_vmx_exit_fixed1{};
        /// @brief stores the entry ctls fixed0 values for sanitization
        bsl::safe_u64 m_vmx_entry_fixed0{};
        /// @brief stores the entry ctls fixed1 values for sanitization
        bsl::safe_u64 m_vmx_entry_fixed1{};
        /// @brief stores the proc2 ctls fixed0 values for sanitization
        bsl::safe_u64 m_vmx_proc2_fixed0{};
        /// @brief stores the proc2 ctls fixed1 values for sanitization
        bsl::safe_u64 m_vmx_proc2_fixed1{};

        /// <!-- description -->
        ///   @brief Returns the row color based on the value of "val"
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam T the type of field to query
        ///   @param val the field to query
        ///   @return Returns the row color based on the value of "val"
        ///
        template<typename T>
        [[nodiscard]] static constexpr auto
        get_row_color(bsl::safe_integral<T> const &val) noexcept -> bsl::string_view
        {
            if (val.is_zero()) {
                return bsl::blk;
            }

            return bsl::rst;
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
        dump_field(bsl::string_view const &str, bsl::safe_integral<T> const &val) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            auto const rowcolor{get_row_color(val)};

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<40s", str};
            bsl::print() << bsl::ylw << "| ";

            if (val.is_valid()) {
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

        /// <!-- description -->
        ///   @brief Stores the provided ES segment state info in the VS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param selector_idx the selector VMCS index to use
        ///   @param selector_val the selector value to write to the VMCS
        ///   @param attrib_idx the attrib VMCS index to use
        ///   @param attrib_val the attrib value to write to the VMCS
        ///   @param limit_idx the limit VMCS index to use
        ///   @param limit_val the limit value to write to the VMCS
        ///   @param base_idx the base VMCS index to use
        ///   @param base_val the base value to write to the VMCS
        ///
        static constexpr void
        set_segment_descriptor(
            intrinsic_t &mut_intrinsic,
            bsl::safe_umx const &selector_idx,
            bsl::safe_u16 const &selector_val,
            bsl::safe_umx const &attrib_idx,
            bsl::safe_u32 const &attrib_val,
            bsl::safe_umx const &limit_idx,
            bsl::safe_u32 const &limit_val,
            bsl::safe_umx const &base_idx,
            bsl::safe_u64 const &base_val) noexcept
        {
            if (selector_val.is_zero()) {
                bsl::expects(mut_intrinsic.vmwr16(selector_idx, {}));
                bsl::expects(mut_intrinsic.vmwr32(attrib_idx, VMCS_UNUSABLE_SEGMENT));
                bsl::expects(mut_intrinsic.vmwr32(limit_idx, {}));
                bsl::expects(mut_intrinsic.vmwr64(base_idx, {}));
            }
            else {
                bsl::expects(mut_intrinsic.vmwr16(selector_idx, selector_val));
                bsl::expects(mut_intrinsic.vmwr32(attrib_idx, attrib_val));
                bsl::expects(mut_intrinsic.vmwr32(limit_idx, limit_val));
                bsl::expects(mut_intrinsic.vmwr64(base_idx, base_val));
            }
        }

        /// <!-- description -->
        ///   @brief Stores the ES segment info in the VS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsic_t to use
        ///   @param selector_idx the selector VMCS index to use
        ///   @param pmut_selector_val the selector value to read from the VMCS
        ///   @param attrib_idx the attrib VMCS index to use
        ///   @param pmut_attrib_val the attrib value to read from the VMCS
        ///   @param limit_idx the limit VMCS index to use
        ///   @param pmut_limit_val the limit value to read from the VMCS
        ///   @param base_idx the base VMCS index to use
        ///   @param pmut_base_val the base value to read from the VMCS
        ///
        static constexpr void
        get_segment_descriptor(
            intrinsic_t const &intrinsic,
            bsl::safe_umx const &selector_idx,
            bsl::uint16 *const pmut_selector_val,
            bsl::safe_umx const &attrib_idx,
            bsl::uint16 *const pmut_attrib_val,
            bsl::safe_umx const &limit_idx,
            bsl::uint32 *const pmut_limit_val,
            bsl::safe_umx const &base_idx,
            bsl::uint64 *const pmut_base_val) noexcept
        {
            bsl::expects(intrinsic.vmrd16(selector_idx, pmut_selector_val));

            if (bsl::safe_u16::magic_0() == *pmut_selector_val) {
                *pmut_attrib_val = {};
                *pmut_limit_val = {};
                *pmut_base_val = {};
            }
            else {
                bsl::expects(intrinsic.vmrd16(attrib_idx, pmut_attrib_val));
                bsl::expects(intrinsic.vmrd32(limit_idx, pmut_limit_val));
                bsl::expects(intrinsic.vmrd64(base_idx, pmut_base_val));
            }
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of the pin_ctls
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of the pin_ctls
        ///
        [[nodiscard]] constexpr auto
        sanitize_pin_ctls(bsl::safe_u64 const &val) noexcept -> bsl::safe_u32
        {
            constexpr auto vmcs_pin_ctls_mask{0x28_u64};
            auto mut_val{val | vmcs_pin_ctls_mask};

            mut_val |= m_vmx_pin_fixed0;
            mut_val &= m_vmx_pin_fixed1;
            return bsl::to_u32(mut_val);
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of the proc_ctls
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of the proc_ctls
        ///
        [[nodiscard]] constexpr auto
        sanitize_proc_ctls(bsl::safe_u64 const &val) noexcept -> bsl::safe_u32
        {
            constexpr auto vmcs_proc_ctls_mask{0x80000000_u64};
            auto mut_val{val | vmcs_proc_ctls_mask};

            mut_val |= m_vmx_proc_fixed0;
            mut_val &= m_vmx_proc_fixed1;
            return bsl::to_u32(mut_val);
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of the exit_ctls
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of the exit_ctls
        ///
        [[nodiscard]] constexpr auto
        sanitize_exit_ctls(bsl::safe_u64 const &val) noexcept -> bsl::safe_u32
        {
            constexpr auto vmcs_exit_ctls_mask{0x3C0204_u64};
            auto mut_val{val | vmcs_exit_ctls_mask};

            mut_val |= m_vmx_exit_fixed0;
            mut_val &= m_vmx_exit_fixed1;
            return bsl::to_u32(mut_val);
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of the entry_ctls
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of the entry_ctls
        ///
        [[nodiscard]] constexpr auto
        sanitize_entry_ctls(bsl::safe_u64 const &val) noexcept -> bsl::safe_u32
        {
            constexpr auto vmcs_entry_ctls_mask{0xC004_u64};
            auto mut_val{val | vmcs_entry_ctls_mask};

            mut_val |= m_vmx_entry_fixed0;
            mut_val &= m_vmx_entry_fixed1;
            return bsl::to_u32(mut_val);
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of the proc2_ctls
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of the proc2_ctls
        ///
        [[nodiscard]] constexpr auto
        sanitize_proc2_ctls(bsl::safe_u64 const &val) noexcept -> bsl::safe_u32
        {
            constexpr auto vmcs_proc2_ctls_mask{0x0_u64};
            auto mut_val{val | vmcs_proc2_ctls_mask};

            mut_val |= m_vmx_proc2_fixed0;
            mut_val &= m_vmx_proc2_fixed1;

            constexpr auto pg_pe{0x80000001_u64};
            constexpr auto unrestricted_guest_mode{0x00000080_u64};
            if ((mut_val & unrestricted_guest_mode).is_pos()) {
                m_vmx_cr0_fixed0 &= ~pg_pe;
            }
            else {
                m_vmx_cr0_fixed0 |= pg_pe;
            }

            return bsl::to_u32(mut_val);
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of CR4
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of CR4
        ///
        [[nodiscard]] constexpr auto
        sanitize_cr0(bsl::safe_u64 const &val) noexcept -> bsl::safe_u64
        {
            auto mut_val{val};
            mut_val |= m_vmx_cr0_fixed0;
            mut_val &= m_vmx_cr0_fixed1;

            return mut_val;
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of CR4
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of CR4
        ///
        [[nodiscard]] constexpr auto
        sanitize_cr4(bsl::safe_u64 const &val) noexcept -> bsl::safe_u64
        {
            auto mut_val{val};
            mut_val |= m_vmx_cr4_fixed0;
            mut_val &= m_vmx_cr4_fixed1;

            constexpr auto vmxe_mask{0x2000_u64};
            return mut_val | vmxe_mask;
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of XCR0
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of XCR0
        ///
        [[nodiscard]] static constexpr auto
        sanitize_xcr0(bsl::safe_u64 const &val) noexcept -> bsl::safe_u64
        {
            constexpr auto efer_mask{0x0000000000000001_u64};
            return val | efer_mask;
        }

        /// <!-- description -->
        ///   @brief Ensures that this VS is loaded
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        ensure_this_vs_is_loaded(tls_t &mut_tls, intrinsic_t const &intrinsic) const noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(mut_tls.ppid == this->assigned_pp());

            if (this->id() == mut_tls.loaded_vsid) {
                return;
            }

            bsl::expects(intrinsic.vmld(&m_vmcs_phys));
            mut_tls.loaded_vsid = this->id().get();
        }

        /// <!-- description -->
        ///   @brief Initializes host specific information in the VMCS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///
        constexpr void
        init_vmcs(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept
        {
            bsl::safe_u64 mut_ctls{};

            auto const revision_id{mut_intrinsic.rdmsr(MSR_VMX_BASIC)};
            bsl::expects(revision_id.is_valid_and_checked());

            m_vmcs->revision_id = bsl::to_u32_unsafe(revision_id).get();
            this->ensure_this_vs_is_loaded(mut_tls, mut_intrinsic);

            bsl::expects(mut_intrinsic.vmcl(&m_vmcs_phys));
            bsl::expects(mut_intrinsic.vmld(&m_vmcs_phys));

            auto const es{mut_intrinsic.es_selector()};
            bsl::expects(mut_intrinsic.vmwr16(VMCS_HOST_ES_SELECTOR, es));
            auto const cs{mut_intrinsic.cs_selector()};
            bsl::expects(mut_intrinsic.vmwr16(VMCS_HOST_CS_SELECTOR, cs));
            auto const ss{mut_intrinsic.ss_selector()};
            bsl::expects(mut_intrinsic.vmwr16(VMCS_HOST_SS_SELECTOR, ss));
            auto const ds{mut_intrinsic.ds_selector()};
            bsl::expects(mut_intrinsic.vmwr16(VMCS_HOST_DS_SELECTOR, ds));
            auto const fs{mut_intrinsic.fs_selector()};
            bsl::expects(mut_intrinsic.vmwr16(VMCS_HOST_FS_SELECTOR, fs));
            auto const gs{mut_intrinsic.gs_selector()};
            bsl::expects(mut_intrinsic.vmwr16(VMCS_HOST_GS_SELECTOR, gs));
            auto const tr{mut_intrinsic.tr_selector()};
            bsl::expects(mut_intrinsic.vmwr16(VMCS_HOST_TR_SELECTOR, tr));

            auto const pat{mut_intrinsic.rdmsr(MSR_PAT)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_PAT, pat));
            auto const efer{mut_intrinsic.rdmsr(MSR_EFER)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_EFER, efer));
            auto const sysenter_cs{mut_intrinsic.rdmsr(MSR_SYSENTER_CS)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_SYSENTER_CS, sysenter_cs));

            auto const cr0{mut_intrinsic.cr0()};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_CR0, cr0));
            auto const cr3{mut_intrinsic.cr3()};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_CR3, cr3));
            auto const cr4{mut_intrinsic.cr4()};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_CR4, cr4));

            auto const fs_base{mut_intrinsic.rdmsr(MSR_FS_BASE)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_FS_BASE, fs_base));
            auto const gs_base{mut_intrinsic.rdmsr(MSR_GS_BASE)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_GS_BASE, gs_base));
            auto const tr_base{bsl::to_u64(mut_tls.mk_state->tr_base)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_TR_BASE, tr_base));

            auto const gdtr_base{bsl::to_u64(mut_tls.mk_state->gdtr.base)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_GDTR_BASE, gdtr_base));
            auto const idtr_base{bsl::to_u64(mut_tls.mk_state->idtr.base)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_IDTR_BASE, idtr_base));

            auto const sysenter_esp{mut_intrinsic.rdmsr(MSR_SYSENTER_ESP)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_SYSENTER_ESP, sysenter_esp));
            auto const sysenter_eip{mut_intrinsic.rdmsr(MSR_SYSENTER_EIP)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_HOST_SYSENTER_EIP, sysenter_eip));

            bsl::expects(mut_intrinsic.vmwrfunc(VMCS_HOST_RIP, &intrinsic_vmexit));

            m_missing_registers.host_star =                       // --
                mut_intrinsic.rdmsr(MSR_STAR).get();              // --
            m_missing_registers.host_lstar =                      // --
                mut_intrinsic.rdmsr(MSR_LSTAR).get();             // --
            m_missing_registers.host_cstar =                      // --
                mut_intrinsic.rdmsr(MSR_CSTAR).get();             // --
            m_missing_registers.host_fmask =                      // --
                mut_intrinsic.rdmsr(MSR_FMASK).get();             // --
            m_missing_registers.host_kernel_gs_base =             // --
                mut_intrinsic.rdmsr(MSR_KERNEL_GS_BASE).get();    // --

            m_vmx_cr0_fixed0 = mut_intrinsic.rdmsr(MSR_VMX_CR0_FIXED0);
            m_vmx_cr0_fixed1 = mut_intrinsic.rdmsr(MSR_VMX_CR0_FIXED1);
            m_vmx_cr4_fixed0 = mut_intrinsic.rdmsr(MSR_VMX_CR4_FIXED0);
            m_vmx_cr4_fixed1 = mut_intrinsic.rdmsr(MSR_VMX_CR4_FIXED1);

            bsl::expects(m_vmx_cr0_fixed0.is_valid_and_checked());
            bsl::expects(m_vmx_cr0_fixed1.is_valid_and_checked());
            bsl::expects(m_vmx_cr4_fixed0.is_valid_and_checked());
            bsl::expects(m_vmx_cr4_fixed1.is_valid_and_checked());

            constexpr auto fixed0_mask{0x00000000FFFFFFFF_u64};
            constexpr auto fixed0_shft{0_u64};
            constexpr auto fixed1_mask{0xFFFFFFFF00000000_u64};
            constexpr auto fixed1_shft{32_u64};

            mut_ctls = mut_intrinsic.rdmsr(MSR_VMX_TRUE_PIN_CTLS);
            m_vmx_pin_fixed0 = (mut_ctls & fixed0_mask) >> fixed0_shft;
            m_vmx_pin_fixed1 = (mut_ctls & fixed1_mask) >> fixed1_shft;
            bsl::expects(m_vmx_pin_fixed0.is_valid_and_checked());
            bsl::expects(m_vmx_pin_fixed1.is_valid_and_checked());

            mut_ctls = mut_intrinsic.rdmsr(MSR_VMX_TRUE_PROC_CTLS);
            m_vmx_proc_fixed0 = (mut_ctls & fixed0_mask) >> fixed0_shft;
            m_vmx_proc_fixed1 = (mut_ctls & fixed1_mask) >> fixed1_shft;
            bsl::expects(m_vmx_proc_fixed0.is_valid_and_checked());
            bsl::expects(m_vmx_proc_fixed1.is_valid_and_checked());

            mut_ctls = mut_intrinsic.rdmsr(MSR_VMX_TRUE_EXIT_CTLS);
            m_vmx_exit_fixed0 = (mut_ctls & fixed0_mask) >> fixed0_shft;
            m_vmx_exit_fixed1 = (mut_ctls & fixed1_mask) >> fixed1_shft;
            bsl::expects(m_vmx_exit_fixed0.is_valid_and_checked());
            bsl::expects(m_vmx_exit_fixed1.is_valid_and_checked());

            mut_ctls = mut_intrinsic.rdmsr(MSR_VMX_TRUE_ENTRY_CTLS);
            m_vmx_entry_fixed0 = (mut_ctls & fixed0_mask) >> fixed0_shft;
            m_vmx_entry_fixed1 = (mut_ctls & fixed1_mask) >> fixed1_shft;
            bsl::expects(m_vmx_entry_fixed0.is_valid_and_checked());
            bsl::expects(m_vmx_entry_fixed1.is_valid_and_checked());

            mut_ctls = mut_intrinsic.rdmsr(MSR_VMX_TRUE_PROC2_CTLS);
            m_vmx_proc2_fixed0 = (mut_ctls & fixed0_mask) >> fixed0_shft;
            m_vmx_proc2_fixed1 = (mut_ctls & fixed1_mask) >> fixed1_shft;
            bsl::expects(m_vmx_proc2_fixed0.is_valid_and_checked());
            bsl::expects(m_vmx_proc2_fixed1.is_valid_and_checked());
        }

    public:
        /// <!-- description -->
        ///   @brief Initializes this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param i the ID for this vs_t
        ///
        constexpr void
        initialize(bsl::safe_u16 const &i) noexcept
        {
            bsl::expects(this->id() == syscall::BF_INVALID_ID);

            bsl::expects(i.is_valid_and_checked());
            bsl::expects(i != syscall::BF_INVALID_ID);

            m_id = ~i;
        }

        /// <!-- description -->
        ///   @brief Release the vs_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///
        constexpr void
        release(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept
        {
            this->deallocate(mut_tls, mut_page_pool);
            m_id = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vs_t
        ///
        [[nodiscard]] constexpr auto
        id() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_id.is_valid_and_checked());
            return ~m_id;
        }

        /// <!-- description -->
        ///   @brief Allocates this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param vmid The ID of the VM to assign the newly allocated vs_t to
        ///   @param vpid The ID of the VP to assign the newly allocated vs_t to
        ///   @param ppid The ID of the PP to assign the newly allocated vs_t to
        ///   @return Returns ID of the newly allocated vs_t
        ///
        [[nodiscard]] constexpr auto
        allocate(
            tls_t &mut_tls,
            page_pool_t &mut_page_pool,
            intrinsic_t &mut_intrinsic,
            bsl::safe_u16 const &vmid,
            bsl::safe_u16 const &vpid,
            bsl::safe_u16 const &ppid) noexcept -> bsl::safe_u16
        {
            bsl::expects(this->id() != syscall::BF_INVALID_ID);
            bsl::expects(allocated_status_t::deallocated == m_allocated);
            bsl::expects(running_status_t::initial == m_status);

            bsl::expects(vmid.is_valid_and_checked());
            bsl::expects(vmid != syscall::BF_INVALID_ID);
            bsl::expects(vpid.is_valid_and_checked());
            bsl::expects(vpid != syscall::BF_INVALID_ID);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);

            m_vmcs = mut_page_pool.template allocate<vmcs_t>(mut_tls);
            if (bsl::unlikely(nullptr == m_vmcs)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_u16::failure();
            }

            m_vmcs_phys = mut_page_pool.virt_to_phys(m_vmcs);
            bsl::expects(m_vmcs_phys.is_valid_and_checked());

            m_assigned_vmid = ~vmid;
            m_assigned_vpid = ~vpid;
            m_assigned_ppid = ~ppid;
            m_allocated = allocated_status_t::allocated;

            this->init_vmcs(mut_tls, mut_intrinsic);
            return this->id();
        }

        /// <!-- description -->
        ///   @brief Deallocates this vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page_pool_t to use
        ///
        constexpr void
        deallocate(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept
        {
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(this->is_active().is_invalid());

            m_missing_registers = {};
            m_gprs = {};

            mut_page_pool.deallocate(mut_tls, m_vmcs);
            m_vmcs = {};
            m_vmcs_phys = {};

            m_assigned_ppid = {};
            m_assigned_vpid = {};
            m_assigned_vmid = {};
            m_status = running_status_t::initial;
            m_allocated = allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vs_t is deallocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vs_t is deallocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_deallocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::deallocated;
        }

        /// <!-- description -->
        ///   @brief Returns true if this vs_t is allocated, false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns true if this vs_t is allocated, false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_allocated() const noexcept -> bool
        {
            return m_allocated == allocated_status_t::allocated;
        }

        /// <!-- description -->
        ///   @brief Sets this vs_t as active.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///
        constexpr void
        set_active(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(syscall::BF_INVALID_ID == mut_tls.active_vsid);

            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, bsl::to_u64(m_gprs.rax));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, bsl::to_u64(m_gprs.rbx));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, bsl::to_u64(m_gprs.rcx));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, bsl::to_u64(m_gprs.rdx));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, bsl::to_u64(m_gprs.rbp));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, bsl::to_u64(m_gprs.rsi));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, bsl::to_u64(m_gprs.rdi));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, bsl::to_u64(m_gprs.r8));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, bsl::to_u64(m_gprs.r9));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, bsl::to_u64(m_gprs.r10));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, bsl::to_u64(m_gprs.r11));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, bsl::to_u64(m_gprs.r12));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, bsl::to_u64(m_gprs.r13));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, bsl::to_u64(m_gprs.r14));
            mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, bsl::to_u64(m_gprs.r15));

            m_active_ppid = ~bsl::to_u16(mut_tls.ppid);
            mut_tls.active_vsid = this->id().get();
        }

        /// <!-- description -->
        ///   @brief Sets this vs_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        set_inactive(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(running_status_t::running != m_status);
            bsl::expects(this->id() == mut_tls.active_vsid);

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

            m_active_ppid = {};
            mut_tls.active_vsid = syscall::BF_INVALID_ID.get();
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vs_t is active on. If the
        ///     vs_t is not active, bsl::safe_u16::failure() is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vs_t is active on. If the
        ///     vs_t is not active, bsl::safe_u16::failure() is returned.
        ///
        [[nodiscard]] constexpr auto
        is_active() const noexcept -> bsl::safe_u16
        {
            if (m_active_ppid.is_pos()) {
                return ~m_active_ppid;
            }

            return bsl::safe_u16::failure();
        }

        /// <!-- description -->
        ///   @brief Returns true if this vs_t is active on the current PP,
        ///     false otherwise
        ///
        /// <!-- inputs/outputs -->
        ///   @param tls the current TLS block
        ///   @return Returns true if this vs_t is active on the current PP,
        ///     false otherwise
        ///
        [[nodiscard]] constexpr auto
        is_active_on_this_pp(tls_t const &tls) const noexcept -> bool
        {
            return tls.ppid == ~m_active_ppid;
        }

        /// <!-- description -->
        ///   @brief Migrates this vs_t from one PP to another
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param ppid the ID of the PP to migrate to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        migrate(tls_t &mut_tls, intrinsic_t const &intrinsic, bsl::safe_u16 const &ppid) noexcept
            -> bsl::errc_type
        {
            bsl::expects(allocated_status_t::allocated == m_allocated);
            bsl::expects(ppid.is_valid_and_checked());
            bsl::expects(ppid != syscall::BF_INVALID_ID);

            auto const ret{this->clear(mut_tls, intrinsic)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            m_assigned_ppid = ~ppid;
            return ret;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VM this vs_t is assigned to. If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VM this vs_t is assigned to If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vm() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vmid.is_valid_and_checked());
            return ~m_assigned_vmid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the VP this vs_t is assigned to. If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the VP this vs_t is assigned to If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_vp() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vpid.is_valid_and_checked());
            return ~m_assigned_vpid;
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP this vs_t is assigned to If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP this vs_t is assigned to If
        ///     vs_t is not assigned, syscall::BF_INVALID_ID is returned.
        ///
        [[nodiscard]] constexpr auto
        assigned_pp() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_ppid.is_valid_and_checked());
            return ~m_assigned_ppid;
        }

        /// <!-- description -->
        ///   @brief Stores the provided state in the vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param state the state to set the vs_t to
        ///
        constexpr void
        state_save_to_vs(
            tls_t &mut_tls,
            intrinsic_t &mut_intrinsic,
            loader::state_save_t const *const state) noexcept
        {
            bsl::expects(nullptr != state);
            this->ensure_this_vs_is_loaded(mut_tls, mut_intrinsic);

            if (mut_tls.active_vsid == this->id()) {
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, bsl::to_u64(state->rax));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, bsl::to_u64(state->rbx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, bsl::to_u64(state->rcx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, bsl::to_u64(state->rdx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, bsl::to_u64(state->rbp));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, bsl::to_u64(state->rsi));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, bsl::to_u64(state->rdi));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, bsl::to_u64(state->r8));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, bsl::to_u64(state->r9));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, bsl::to_u64(state->r10));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, bsl::to_u64(state->r11));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, bsl::to_u64(state->r12));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, bsl::to_u64(state->r13));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, bsl::to_u64(state->r14));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, bsl::to_u64(state->r15));
            }
            else {
                m_gprs.rax = state->rax;
                m_gprs.rbx = state->rbx;
                m_gprs.rcx = state->rcx;
                m_gprs.rdx = state->rdx;
                m_gprs.rbp = state->rbp;
                m_gprs.rsi = state->rsi;
                m_gprs.rdi = state->rdi;
                m_gprs.r8 = state->r8;
                m_gprs.r9 = state->r9;
                m_gprs.r10 = state->r10;
                m_gprs.r11 = state->r11;
                m_gprs.r12 = state->r12;
                m_gprs.r13 = state->r13;
                m_gprs.r14 = state->r14;
                m_gprs.r15 = state->r15;
            }

            auto const rsp{bsl::to_u64(state->rsp)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_RSP, rsp));
            auto const rip{bsl::to_u64(state->rip)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_RIP, rip));
            auto const rflags{bsl::to_u64(state->rflags)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_RFLAGS, rflags));

            auto const gdtr_limit{bsl::to_u32(state->gdtr.limit)};
            bsl::expects(mut_intrinsic.vmwr32(VMCS_GUEST_GDTR_LIMIT, gdtr_limit));
            auto const gdtr_base{bsl::to_u64(state->gdtr.base)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_GDTR_BASE, gdtr_base));

            auto const idtr_limit{bsl::to_u32(state->idtr.limit)};
            bsl::expects(mut_intrinsic.vmwr32(VMCS_GUEST_IDTR_LIMIT, idtr_limit));
            auto const idtr_base{bsl::to_u64(state->idtr.base)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_IDTR_BASE, idtr_base));

            this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_ES_SELECTOR,
                bsl::to_u16(state->es_selector),
                VMCS_GUEST_ES_ACCESS_RIGHTS,
                bsl::to_u32(state->es_attrib),
                VMCS_GUEST_ES_LIMIT,
                bsl::to_u32(state->es_limit),
                VMCS_GUEST_ES_BASE,
                bsl::to_u64(state->es_base));

            this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_CS_SELECTOR,
                bsl::to_u16(state->cs_selector),
                VMCS_GUEST_CS_ACCESS_RIGHTS,
                bsl::to_u32(state->cs_attrib),
                VMCS_GUEST_CS_LIMIT,
                bsl::to_u32(state->cs_limit),
                VMCS_GUEST_CS_BASE,
                bsl::to_u64(state->cs_base));

            this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_SS_SELECTOR,
                bsl::to_u16(state->ss_selector),
                VMCS_GUEST_SS_ACCESS_RIGHTS,
                bsl::to_u32(state->ss_attrib),
                VMCS_GUEST_SS_LIMIT,
                bsl::to_u32(state->ss_limit),
                VMCS_GUEST_SS_BASE,
                bsl::to_u64(state->ss_base));

            this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_DS_SELECTOR,
                bsl::to_u16(state->ds_selector),
                VMCS_GUEST_DS_ACCESS_RIGHTS,
                bsl::to_u32(state->ds_attrib),
                VMCS_GUEST_DS_LIMIT,
                bsl::to_u32(state->ds_limit),
                VMCS_GUEST_DS_BASE,
                bsl::to_u64(state->ds_base));

            this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_FS_SELECTOR,
                bsl::to_u16(state->fs_selector),
                VMCS_GUEST_FS_ACCESS_RIGHTS,
                bsl::to_u32(state->fs_attrib),
                VMCS_GUEST_FS_LIMIT,
                bsl::to_u32(state->fs_limit),
                VMCS_GUEST_FS_BASE,
                bsl::to_u64(state->fs_base));

            this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_GS_SELECTOR,
                bsl::to_u16(state->gs_selector),
                VMCS_GUEST_GS_ACCESS_RIGHTS,
                bsl::to_u32(state->gs_attrib),
                VMCS_GUEST_GS_LIMIT,
                bsl::to_u32(state->gs_limit),
                VMCS_GUEST_GS_BASE,
                bsl::to_u64(state->gs_base));

            this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_LDTR_SELECTOR,
                bsl::to_u16(state->ldtr_selector),
                VMCS_GUEST_LDTR_ACCESS_RIGHTS,
                bsl::to_u32(state->ldtr_attrib),
                VMCS_GUEST_LDTR_LIMIT,
                bsl::to_u32(state->ldtr_limit),
                VMCS_GUEST_LDTR_BASE,
                bsl::to_u64(state->ldtr_base));

            this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_TR_SELECTOR,
                bsl::to_u16(state->tr_selector),
                VMCS_GUEST_TR_ACCESS_RIGHTS,
                bsl::to_u32(state->tr_attrib),
                VMCS_GUEST_TR_LIMIT,
                bsl::to_u32(state->tr_limit),
                VMCS_GUEST_TR_BASE,
                bsl::to_u64(state->tr_base));

            auto const cr0{bsl::to_u64(this->sanitize_cr0(bsl::to_u64(state->cr0)))};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_CR0, cr0));

            m_missing_registers.guest_cr2 = state->cr2;

            auto const cr3{bsl::to_u64(state->cr3)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_CR3, cr3));
            auto const cr4{bsl::to_u64(this->sanitize_cr4(bsl::to_u64(state->cr4)))};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_CR4, cr4));

            m_missing_registers.guest_cr8 = state->cr8;
            m_missing_registers.guest_xcr0 = sanitize_xcr0(bsl::to_u64(state->xcr0)).get();

            m_missing_registers.guest_dr0 = state->dr0;
            m_missing_registers.guest_dr1 = state->dr1;
            m_missing_registers.guest_dr2 = state->dr2;
            m_missing_registers.guest_dr3 = state->dr3;
            m_missing_registers.guest_dr6 = state->dr6;

            auto const dr7{bsl::to_u64(state->dr7)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_DR7, dr7));

            auto const pat{bsl::to_u64(state->msr_pat)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_PAT, pat));
            auto const efer{bsl::to_u64(state->msr_efer)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_EFER, efer));
            auto const sysenter_cs{bsl::to_u64(state->msr_sysenter_cs)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_SYSENTER_CS, sysenter_cs));
            auto const fs_base{bsl::to_u64(state->msr_fs_base)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_FS_BASE, fs_base));
            auto const gs_base{bsl::to_u64(state->msr_gs_base)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_GS_BASE, gs_base));
            auto const sysenter_esp{bsl::to_u64(state->msr_sysenter_esp)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_SYSENTER_ESP, sysenter_esp));
            auto const sysenter_eip{bsl::to_u64(state->msr_sysenter_eip)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_SYSENTER_EIP, sysenter_eip));
            auto const debugctl{bsl::to_u64(state->msr_debugctl)};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_DEBUGCTL, debugctl));

            m_missing_registers.guest_star = state->msr_star;
            m_missing_registers.guest_lstar = state->msr_lstar;
            m_missing_registers.guest_cstar = state->msr_cstar;
            m_missing_registers.guest_fmask = state->msr_fmask;
            m_missing_registers.guest_kernel_gs_base = state->msr_kernel_gs_base;
        }

        /// <!-- description -->
        ///   @brief Stores the vs_t state in the provided state save
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param pmut_state the state save to store the vs_t state to
        ///
        constexpr void
        vs_to_state_save(
            tls_t &mut_tls,
            intrinsic_t const &intrinsic,
            loader::state_save_t *const pmut_state) const noexcept
        {
            bsl::expects(nullptr != pmut_state);
            this->ensure_this_vs_is_loaded(mut_tls, intrinsic);

            if (mut_tls.active_vsid == this->id()) {
                pmut_state->rax = intrinsic.tls_reg(syscall::TLS_OFFSET_RAX).get();
                pmut_state->rbx = intrinsic.tls_reg(syscall::TLS_OFFSET_RBX).get();
                pmut_state->rcx = intrinsic.tls_reg(syscall::TLS_OFFSET_RCX).get();
                pmut_state->rdx = intrinsic.tls_reg(syscall::TLS_OFFSET_RDX).get();
                pmut_state->rbp = intrinsic.tls_reg(syscall::TLS_OFFSET_RBP).get();
                pmut_state->rsi = intrinsic.tls_reg(syscall::TLS_OFFSET_RSI).get();
                pmut_state->rdi = intrinsic.tls_reg(syscall::TLS_OFFSET_RDI).get();
                pmut_state->r8 = intrinsic.tls_reg(syscall::TLS_OFFSET_R8).get();
                pmut_state->r9 = intrinsic.tls_reg(syscall::TLS_OFFSET_R9).get();
                pmut_state->r10 = intrinsic.tls_reg(syscall::TLS_OFFSET_R10).get();
                pmut_state->r11 = intrinsic.tls_reg(syscall::TLS_OFFSET_R11).get();
                pmut_state->r12 = intrinsic.tls_reg(syscall::TLS_OFFSET_R12).get();
                pmut_state->r13 = intrinsic.tls_reg(syscall::TLS_OFFSET_R13).get();
                pmut_state->r14 = intrinsic.tls_reg(syscall::TLS_OFFSET_R14).get();
                pmut_state->r15 = intrinsic.tls_reg(syscall::TLS_OFFSET_R15).get();
            }
            else {
                pmut_state->rax = m_gprs.rax;
                pmut_state->rbx = m_gprs.rbx;
                pmut_state->rcx = m_gprs.rcx;
                pmut_state->rdx = m_gprs.rdx;
                pmut_state->rbp = m_gprs.rbp;
                pmut_state->rsi = m_gprs.rsi;
                pmut_state->rdi = m_gprs.rdi;
                pmut_state->r8 = m_gprs.r8;
                pmut_state->r9 = m_gprs.r9;
                pmut_state->r10 = m_gprs.r10;
                pmut_state->r11 = m_gprs.r11;
                pmut_state->r12 = m_gprs.r12;
                pmut_state->r13 = m_gprs.r13;
                pmut_state->r14 = m_gprs.r14;
                pmut_state->r15 = m_gprs.r15;
            }

            auto *const pmut_rsp{&pmut_state->rsp};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_RSP, pmut_rsp));
            auto *const pmut_rip{&pmut_state->rip};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_RIP, pmut_rip));
            auto *const pmut_rflags{&pmut_state->rflags};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_RFLAGS, pmut_rflags));

            auto *const pmut_gdtr_limit{&pmut_state->gdtr.limit};
            bsl::expects(intrinsic.vmrd16(VMCS_GUEST_GDTR_LIMIT, pmut_gdtr_limit));
            auto *const pmut_gdtr_base{&pmut_state->gdtr.base};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_GDTR_BASE, pmut_gdtr_base));
            auto *const pmut_idtr_limit{&pmut_state->idtr.limit};
            bsl::expects(intrinsic.vmrd16(VMCS_GUEST_IDTR_LIMIT, pmut_idtr_limit));
            auto *const pmut_idtr_base{&pmut_state->idtr.base};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_IDTR_BASE, pmut_idtr_base));

            this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_ES_SELECTOR,
                &pmut_state->es_selector,
                VMCS_GUEST_ES_ACCESS_RIGHTS,
                &pmut_state->es_attrib,
                VMCS_GUEST_ES_LIMIT,
                &pmut_state->es_limit,
                VMCS_GUEST_ES_BASE,
                &pmut_state->es_base);

            this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_CS_SELECTOR,
                &pmut_state->cs_selector,
                VMCS_GUEST_CS_ACCESS_RIGHTS,
                &pmut_state->cs_attrib,
                VMCS_GUEST_CS_LIMIT,
                &pmut_state->cs_limit,
                VMCS_GUEST_CS_BASE,
                &pmut_state->cs_base);

            this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_SS_SELECTOR,
                &pmut_state->ss_selector,
                VMCS_GUEST_SS_ACCESS_RIGHTS,
                &pmut_state->ss_attrib,
                VMCS_GUEST_SS_LIMIT,
                &pmut_state->ss_limit,
                VMCS_GUEST_SS_BASE,
                &pmut_state->ss_base);

            this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_DS_SELECTOR,
                &pmut_state->ds_selector,
                VMCS_GUEST_DS_ACCESS_RIGHTS,
                &pmut_state->ds_attrib,
                VMCS_GUEST_DS_LIMIT,
                &pmut_state->ds_limit,
                VMCS_GUEST_DS_BASE,
                &pmut_state->ds_base);

            this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_FS_SELECTOR,
                &pmut_state->fs_selector,
                VMCS_GUEST_FS_ACCESS_RIGHTS,
                &pmut_state->fs_attrib,
                VMCS_GUEST_FS_LIMIT,
                &pmut_state->fs_limit,
                VMCS_GUEST_FS_BASE,
                &pmut_state->fs_base);

            this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_GS_SELECTOR,
                &pmut_state->gs_selector,
                VMCS_GUEST_GS_ACCESS_RIGHTS,
                &pmut_state->gs_attrib,
                VMCS_GUEST_GS_LIMIT,
                &pmut_state->gs_limit,
                VMCS_GUEST_GS_BASE,
                &pmut_state->gs_base);

            this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_LDTR_SELECTOR,
                &pmut_state->ldtr_selector,
                VMCS_GUEST_LDTR_ACCESS_RIGHTS,
                &pmut_state->ldtr_attrib,
                VMCS_GUEST_LDTR_LIMIT,
                &pmut_state->ldtr_limit,
                VMCS_GUEST_LDTR_BASE,
                &pmut_state->ldtr_base);

            this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_TR_SELECTOR,
                &pmut_state->tr_selector,
                VMCS_GUEST_TR_ACCESS_RIGHTS,
                &pmut_state->tr_attrib,
                VMCS_GUEST_TR_LIMIT,
                &pmut_state->tr_limit,
                VMCS_GUEST_TR_BASE,
                &pmut_state->tr_base);

            auto *const pmut_cr0{&pmut_state->cr0};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_CR0, pmut_cr0));

            pmut_state->cr2 = m_missing_registers.guest_cr2;

            auto *const pmut_cr3{&pmut_state->cr3};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_CR3, pmut_cr3));
            auto *const pmut_cr4{&pmut_state->cr4};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_CR4, pmut_cr4));

            pmut_state->cr8 = m_missing_registers.guest_cr8;
            pmut_state->xcr0 = m_missing_registers.guest_xcr0;

            pmut_state->dr0 = m_missing_registers.guest_dr0;
            pmut_state->dr1 = m_missing_registers.guest_dr1;
            pmut_state->dr2 = m_missing_registers.guest_dr2;
            pmut_state->dr3 = m_missing_registers.guest_dr3;
            pmut_state->dr6 = m_missing_registers.guest_dr6;

            auto *const pmut_dr7{&pmut_state->dr7};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_DR7, pmut_dr7));

            auto *const pmut_pat{&pmut_state->msr_pat};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_PAT, pmut_pat));
            auto *const pmut_efer{&pmut_state->msr_efer};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_EFER, pmut_efer));
            auto *const pmut_sysenter_cs{&pmut_state->msr_sysenter_cs};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_SYSENTER_CS, pmut_sysenter_cs));
            auto *const pmut_fs_base{&pmut_state->msr_fs_base};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_FS_BASE, pmut_fs_base));
            auto *const pmut_gs_base{&pmut_state->msr_gs_base};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_GS_BASE, pmut_gs_base));
            auto *const pmut_sysenter_esp{&pmut_state->msr_sysenter_esp};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_SYSENTER_ESP, pmut_sysenter_esp));
            auto *const pmut_sysenter_eip{&pmut_state->msr_sysenter_eip};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_SYSENTER_EIP, pmut_sysenter_eip));
            auto *const pmut_debugctl{&pmut_state->msr_debugctl};
            bsl::expects(intrinsic.vmrd64(VMCS_GUEST_DEBUGCTL, pmut_debugctl));

            pmut_state->msr_star = m_missing_registers.guest_star;
            pmut_state->msr_lstar = m_missing_registers.guest_lstar;
            pmut_state->msr_cstar = m_missing_registers.guest_cstar;
            pmut_state->msr_fmask = m_missing_registers.guest_fmask;
            pmut_state->msr_kernel_gs_base = m_missing_registers.guest_kernel_gs_base;
        }

        /// <!-- description -->
        ///   @brief Reads a field from the vs_t given a bf_reg_t
        ///     defining the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param reg a bf_reg_t defining the field to read from the vs_t
        ///   @return Returns the value of the requested field from the
        ///     vs_t or bsl::safe_umx::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        read(tls_t &mut_tls, intrinsic_t const &intrinsic, syscall::bf_reg_t const reg)
            const noexcept -> bsl::safe_umx
        {
            bsl::safe_u64 mut_val{};
            bsl::errc_type mut_ret{bsl::errc_failure};

            this->ensure_this_vs_is_loaded(mut_tls, intrinsic);

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_unsupported: {
                    bsl::error() << "unsupported bf_reg_t\n" << bsl::here();
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rax: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RAX);
                    }

                    return bsl::to_u64(m_gprs.rax);
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RBX);
                    }

                    return bsl::to_u64(m_gprs.rbx);
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RCX);
                    }

                    return bsl::to_u64(m_gprs.rcx);
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RDX);
                    }

                    return bsl::to_u64(m_gprs.rdx);
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RBP);
                    }

                    return bsl::to_u64(m_gprs.rbp);
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RSI);
                    }

                    return bsl::to_u64(m_gprs.rsi);
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RDI);
                    }

                    return bsl::to_u64(m_gprs.rdi);
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R8);
                    }

                    return bsl::to_u64(m_gprs.r8);
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R9);
                    }

                    return bsl::to_u64(m_gprs.r9);
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R10);
                    }

                    return bsl::to_u64(m_gprs.r10);
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R11);
                    }

                    return bsl::to_u64(m_gprs.r11);
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R12);
                    }

                    return bsl::to_u64(m_gprs.r12);
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R13);
                    }

                    return bsl::to_u64(m_gprs.r13);
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R14);
                    }

                    return bsl::to_u64(m_gprs.r14);
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    if (mut_tls.active_vsid == this->id()) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R15);
                    }

                    return bsl::to_u64(m_gprs.r15);
                }

                case syscall::bf_reg_t::bf_reg_t_cr2: {
                    return bsl::to_u64(m_missing_registers.guest_cr2);
                }

                case syscall::bf_reg_t::bf_reg_t_dr6: {
                    return bsl::to_u64(m_missing_registers.guest_dr6);
                }

                case syscall::bf_reg_t::bf_reg_t_star: {
                    return bsl::to_u64(m_missing_registers.guest_star);
                }

                case syscall::bf_reg_t::bf_reg_t_lstar: {
                    return bsl::to_u64(m_missing_registers.guest_lstar);
                }

                case syscall::bf_reg_t::bf_reg_t_cstar: {
                    return bsl::to_u64(m_missing_registers.guest_cstar);
                }

                case syscall::bf_reg_t::bf_reg_t_fmask: {
                    return bsl::to_u64(m_missing_registers.guest_fmask);
                }

                case syscall::bf_reg_t::bf_reg_t_kernel_gs_base: {
                    return bsl::to_u64(m_missing_registers.guest_kernel_gs_base);
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier: {
                    mut_ret = intrinsic.vmrd64(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_posted_interrupt_notification_vector: {
                    mut_ret =
                        intrinsic.vmrd64(VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eptp_index: {
                    mut_ret = intrinsic.vmrd64(VMCS_EPTP_INDEX, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_selector: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_ES_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_selector: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_CS_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_selector: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_SS_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_selector: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_DS_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_selector: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_FS_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_selector: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_GS_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_selector: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_LDTR_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_selector: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_TR_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_interrupt_status: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_INTERRUPT_STATUS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pml_index: {
                    mut_ret = intrinsic.vmrd64(VMCS_PML_INDEX, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_io_bitmap_a: {
                    mut_ret = intrinsic.vmrd64(VMCS_ADDRESS_OF_IO_BITMAP_A, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_io_bitmap_b: {
                    mut_ret = intrinsic.vmrd64(VMCS_ADDRESS_OF_IO_BITMAP_B, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_msr_bitmaps: {
                    mut_ret = intrinsic.vmrd64(VMCS_ADDRESS_OF_MSR_BITMAPS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_store_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMEXIT_MSR_STORE_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_load_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMEXIT_MSR_LOAD_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_msr_load_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMENTRY_MSR_LOAD_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_executive_vmcs_pointer: {
                    mut_ret = intrinsic.vmrd64(VMCS_EXECUTIVE_VMCS_POINTER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pml_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_PML_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tsc_offset: {
                    mut_ret = intrinsic.vmrd64(VMCS_TSC_OFFSET, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_apic_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_VIRTUAL_APIC_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_apic_access_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_APIC_ACCESS_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_posted_interrupt_descriptor_address: {
                    mut_ret =
                        intrinsic.vmrd64(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vm_function_controls: {
                    mut_ret = intrinsic.vmrd64(VMCS_VM_FUNCTION_CONTROLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ept_pointer: {
                    mut_ret = intrinsic.vmrd64(VMCS_EPT_POINTER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap0: {
                    mut_ret = intrinsic.vmrd64(VMCS_EOI_EXIT_BITMAP0, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap1: {
                    mut_ret = intrinsic.vmrd64(VMCS_EOI_EXIT_BITMAP1, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap2: {
                    mut_ret = intrinsic.vmrd64(VMCS_EOI_EXIT_BITMAP2, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap3: {
                    mut_ret = intrinsic.vmrd64(VMCS_EOI_EXIT_BITMAP3, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eptp_list_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_EPTP_LIST_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmread_bitmap_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMREAD_BITMAP_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmwrite_bitmap_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMWRITE_BITMAP_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_virt_exception_information_address: {
                    mut_ret =
                        intrinsic.vmrd64(VMCS_VIRT_EXCEPTION_INFORMATION_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_xss_exiting_bitmap: {
                    mut_ret = intrinsic.vmrd64(VMCS_XSS_EXITING_BITMAP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_encls_exiting_bitmap: {
                    mut_ret = intrinsic.vmrd64(VMCS_ENCLS_EXITING_BITMAP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_sub_page_permission_table_pointer: {
                    mut_ret =
                        intrinsic.vmrd64(VMCS_SUB_PAGE_PERMISSION_TABLE_POINTER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tls_multiplier: {
                    mut_ret = intrinsic.vmrd64(VMCS_TLS_MULTIPLIER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_physical_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_PHYSICAL_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMCS_LINK_POINTER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_debugctl: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_DEBUGCTL, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pat: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_PAT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_efer: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_EFER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_perf_global_ctrl: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_PERF_GLOBAL_CTRL, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pdpte0: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_PDPTE0, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pdpte1: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_PDPTE1, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pdpte2: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_PDPTE2, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pdpte3: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_PDPTE3, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_bndcfgs: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_BNDCFGS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rtit_ctl: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_RTIT_CTL, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls: {
                    mut_ret = intrinsic.vmrd64(VMCS_PIN_BASED_VM_EXECUTION_CTLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls: {
                    mut_ret =
                        intrinsic.vmrd64(VMCS_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exception_bitmap: {
                    mut_ret = intrinsic.vmrd64(VMCS_EXCEPTION_BITMAP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_page_fault_error_code_mask: {
                    mut_ret = intrinsic.vmrd64(VMCS_PAGE_FAULT_ERROR_CODE_MASK, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_page_fault_error_code_match: {
                    mut_ret = intrinsic.vmrd64(VMCS_PAGE_FAULT_ERROR_CODE_MATCH, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_count: {
                    mut_ret = intrinsic.vmrd64(VMCS_CR3_TARGET_COUNT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_ctls: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMEXIT_CTLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_store_count: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMEXIT_MSR_STORE_COUNT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_load_count: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMEXIT_MSR_LOAD_COUNT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_ctls: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMENTRY_CTLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_msr_load_count: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMENTRY_MSR_LOAD_COUNT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_interrupt_information_field: {
                    mut_ret =
                        intrinsic.vmrd64(VMCS_VMENTRY_INTERRUPT_INFORMATION_FIELD, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_exception_error_code: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMENTRY_EXCEPTION_ERROR_CODE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_instruction_length: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMENTRY_INSTRUCTION_LENGTH, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tpr_threshold: {
                    mut_ret = intrinsic.vmrd64(VMCS_TPR_THRESHOLD, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls: {
                    mut_ret = intrinsic.vmrd64(
                        VMCS_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ple_gap: {
                    mut_ret = intrinsic.vmrd64(VMCS_PLE_GAP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ple_window: {
                    mut_ret = intrinsic.vmrd64(VMCS_PLE_WINDOW, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vm_instruction_error: {
                    mut_ret = intrinsic.vmrd64(VMCS_VM_INSTRUCTION_ERROR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exit_reason: {
                    mut_ret = intrinsic.vmrd64(VMCS_EXIT_REASON, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_interruption_information: {
                    mut_ret =
                        intrinsic.vmrd64(VMCS_VMEXIT_INTERRUPTION_INFORMATION, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_interruption_error_code: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idt_vectoring_information_field: {
                    mut_ret =
                        intrinsic.vmrd64(VMCS_IDT_VECTORING_INFORMATION_FIELD, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idt_vectoring_error_code: {
                    mut_ret = intrinsic.vmrd64(VMCS_IDT_VECTORING_ERROR_CODE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_instruction_length: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMEXIT_INSTRUCTION_LENGTH, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_instruction_information: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMEXIT_INSTRUCTION_INFORMATION, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_limit: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_ES_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_limit: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_CS_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_limit: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_SS_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_limit: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_DS_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_limit: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_FS_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_limit: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_GS_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_limit: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_LDTR_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_limit: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_TR_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_limit: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_GDTR_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_limit: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_IDTR_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_attrib: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_ES_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_attrib: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_CS_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_attrib: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_SS_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_attrib: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_DS_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_attrib: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_FS_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_attrib: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_GS_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_attrib: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_LDTR_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_attrib: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_TR_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_interruptibility_state: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_INTERRUPTIBILITY_STATE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_activity_state: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_ACTIVITY_STATE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_smbase: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_SMBASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_cs: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_SYSENTER_CS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmx_preemption_timer_value: {
                    mut_ret = intrinsic.vmrd64(VMCS_VMX_PREEMPTION_TIMER_VALUE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0_guest_host_mask: {
                    mut_ret = intrinsic.vmrd64(VMCS_CR0_GUEST_HOST_MASK, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4_guest_host_mask: {
                    mut_ret = intrinsic.vmrd64(VMCS_CR4_GUEST_HOST_MASK, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0_read_shadow: {
                    mut_ret = intrinsic.vmrd64(VMCS_CR0_READ_SHADOW, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4_read_shadow: {
                    mut_ret = intrinsic.vmrd64(VMCS_CR4_READ_SHADOW, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value0: {
                    mut_ret = intrinsic.vmrd64(VMCS_CR3_TARGET_VALUE0, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value1: {
                    mut_ret = intrinsic.vmrd64(VMCS_CR3_TARGET_VALUE1, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value2: {
                    mut_ret = intrinsic.vmrd64(VMCS_CR3_TARGET_VALUE2, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value3: {
                    mut_ret = intrinsic.vmrd64(VMCS_CR3_TARGET_VALUE3, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exit_qualification: {
                    mut_ret = intrinsic.vmrd64(VMCS_EXIT_QUALIFICATION, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rcx: {
                    mut_ret = intrinsic.vmrd64(VMCS_IO_RCX, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rsi: {
                    mut_ret = intrinsic.vmrd64(VMCS_IO_RSI, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rdi: {
                    mut_ret = intrinsic.vmrd64(VMCS_IO_RDI, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rip: {
                    mut_ret = intrinsic.vmrd64(VMCS_IO_RIP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_linear_address: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_LINEAR_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_CR0, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_CR3, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_CR4, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_base: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_ES_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_base: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_CS_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_base: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_SS_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_base: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_DS_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_base: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_FS_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_base: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_GS_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_base: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_LDTR_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_base: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_TR_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_base: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_GDTR_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_base: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_IDTR_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_dr7: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_DR7, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rsp: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_RSP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rip: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_RIP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rflags: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_RFLAGS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pending_debug_exceptions: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_esp: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_SYSENTER_ESP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_eip: {
                    mut_ret = intrinsic.vmrd64(VMCS_GUEST_SYSENTER_EIP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr8: {
                    return bsl::to_u64(m_missing_registers.guest_cr8);
                }

                case syscall::bf_reg_t::bf_reg_t_dr0: {
                    return bsl::to_u64(m_missing_registers.guest_dr0);
                }

                case syscall::bf_reg_t::bf_reg_t_dr1: {
                    return bsl::to_u64(m_missing_registers.guest_dr1);
                }

                case syscall::bf_reg_t::bf_reg_t_dr2: {
                    return bsl::to_u64(m_missing_registers.guest_dr2);
                }

                case syscall::bf_reg_t::bf_reg_t_dr3: {
                    return bsl::to_u64(m_missing_registers.guest_dr3);
                }

                case syscall::bf_reg_t::bf_reg_t_xcr0: {
                    return bsl::to_u64(m_missing_registers.guest_xcr0);
                }

                case syscall::bf_reg_t::bf_reg_t_invalid: {
                    bsl::error() << "invalid bf_reg_t\n" << bsl::here();
                    break;
                }
            }

            return mut_val;
        }

        /// <!-- description -->
        ///   @brief Writes a field to the vs_t given a bf_reg_t
        ///     defining the field and a value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param reg a bf_reg_t defining the field to write to the vs_t
        ///   @param val the value to write to the vs_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        write(
            tls_t &mut_tls,
            intrinsic_t &mut_intrinsic,
            syscall::bf_reg_t const reg,
            bsl::safe_umx const &val) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{bsl::errc_failure};

            bsl::expects(val.is_valid_and_checked());
            this->ensure_this_vs_is_loaded(mut_tls, mut_intrinsic);

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_unsupported: {
                    bsl::error() << "unsupported bf_reg_t\n" << bsl::here();
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rax: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, val);
                    }
                    else {
                        m_gprs.rax = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, val);
                    }
                    else {
                        m_gprs.rbx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, val);
                    }
                    else {
                        m_gprs.rcx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, val);
                    }
                    else {
                        m_gprs.rdx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, val);
                    }
                    else {
                        m_gprs.rbp = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, val);
                    }
                    else {
                        m_gprs.rsi = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, val);
                    }
                    else {
                        m_gprs.rdi = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, val);
                    }
                    else {
                        m_gprs.r8 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, val);
                    }
                    else {
                        m_gprs.r9 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, val);
                    }
                    else {
                        m_gprs.r10 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, val);
                    }
                    else {
                        m_gprs.r11 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, val);
                    }
                    else {
                        m_gprs.r12 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, val);
                    }
                    else {
                        m_gprs.r13 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, val);
                    }
                    else {
                        m_gprs.r14 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    if (mut_tls.active_vsid == this->id()) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, val);
                    }
                    else {
                        m_gprs.r15 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cr2: {
                    m_missing_registers.guest_cr2 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr6: {
                    m_missing_registers.guest_dr6 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_star: {
                    m_missing_registers.guest_star = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_lstar: {
                    m_missing_registers.guest_lstar = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_cstar: {
                    m_missing_registers.guest_cstar = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_fmask: {
                    m_missing_registers.guest_fmask = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_kernel_gs_base: {
                    m_missing_registers.guest_kernel_gs_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier: {
                    mut_ret =
                        mut_intrinsic.vmwr16(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_posted_interrupt_notification_vector: {
                    mut_ret = mut_intrinsic.vmwr16(
                        VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eptp_index: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_EPTP_INDEX, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_selector: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_GUEST_ES_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_selector: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_GUEST_CS_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_selector: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_GUEST_SS_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_selector: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_GUEST_DS_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_selector: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_GUEST_FS_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_selector: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_GUEST_GS_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_selector: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_GUEST_LDTR_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_selector: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_GUEST_TR_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_interrupt_status: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_GUEST_INTERRUPT_STATUS, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pml_index: {
                    mut_ret = mut_intrinsic.vmwr16(VMCS_PML_INDEX, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_io_bitmap_a: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_ADDRESS_OF_IO_BITMAP_A, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_io_bitmap_b: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_ADDRESS_OF_IO_BITMAP_B, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_msr_bitmaps: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_ADDRESS_OF_MSR_BITMAPS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_store_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_VMEXIT_MSR_STORE_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_load_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_VMEXIT_MSR_LOAD_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_msr_load_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_VMENTRY_MSR_LOAD_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_executive_vmcs_pointer: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_EXECUTIVE_VMCS_POINTER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pml_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_PML_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tsc_offset: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_TSC_OFFSET, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_apic_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_VIRTUAL_APIC_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_apic_access_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_APIC_ACCESS_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_posted_interrupt_descriptor_address: {
                    mut_ret = mut_intrinsic.vmwr64(
                        VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vm_function_controls: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_VM_FUNCTION_CONTROLS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ept_pointer: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_EPT_POINTER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap0: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_EOI_EXIT_BITMAP0, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap1: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_EOI_EXIT_BITMAP1, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap2: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_EOI_EXIT_BITMAP2, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap3: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_EOI_EXIT_BITMAP3, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eptp_list_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_EPTP_LIST_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmread_bitmap_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_VMREAD_BITMAP_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmwrite_bitmap_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_VMWRITE_BITMAP_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_virt_exception_information_address: {
                    mut_ret = mut_intrinsic.vmwr64(
                        VMCS_VIRT_EXCEPTION_INFORMATION_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_xss_exiting_bitmap: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_XSS_EXITING_BITMAP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_encls_exiting_bitmap: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_ENCLS_EXITING_BITMAP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_sub_page_permission_table_pointer: {
                    mut_ret = mut_intrinsic.vmwr64(
                        VMCS_SUB_PAGE_PERMISSION_TABLE_POINTER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tls_multiplier: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_TLS_MULTIPLIER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_physical_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_PHYSICAL_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_VMCS_LINK_POINTER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_debugctl: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_DEBUGCTL, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pat: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_PAT, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_efer: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_EFER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_perf_global_ctrl: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_PERF_GLOBAL_CTRL, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pdpte0: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_PDPTE0, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pdpte1: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_PDPTE1, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pdpte2: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_PDPTE2, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pdpte3: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_PDPTE3, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_bndcfgs: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_BNDCFGS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rtit_ctl: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_RTIT_CTL, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls: {
                    mut_ret = mut_intrinsic.vmwr32(
                        VMCS_PIN_BASED_VM_EXECUTION_CTLS, sanitize_pin_ctls(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls: {
                    mut_ret = mut_intrinsic.vmwr32(
                        VMCS_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS, sanitize_proc_ctls(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exception_bitmap: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_EXCEPTION_BITMAP, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_page_fault_error_code_mask: {
                    mut_ret =
                        mut_intrinsic.vmwr32(VMCS_PAGE_FAULT_ERROR_CODE_MASK, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_page_fault_error_code_match: {
                    mut_ret =
                        mut_intrinsic.vmwr32(VMCS_PAGE_FAULT_ERROR_CODE_MATCH, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_count: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_CR3_TARGET_COUNT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_ctls: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_VMEXIT_CTLS, sanitize_exit_ctls(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_store_count: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_VMEXIT_MSR_STORE_COUNT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_load_count: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_VMEXIT_MSR_LOAD_COUNT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_ctls: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_VMENTRY_CTLS, sanitize_entry_ctls(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_msr_load_count: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_VMENTRY_MSR_LOAD_COUNT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_interrupt_information_field: {
                    mut_ret = mut_intrinsic.vmwr32(
                        VMCS_VMENTRY_INTERRUPT_INFORMATION_FIELD, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_exception_error_code: {
                    mut_ret =
                        mut_intrinsic.vmwr32(VMCS_VMENTRY_EXCEPTION_ERROR_CODE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_instruction_length: {
                    mut_ret =
                        mut_intrinsic.vmwr32(VMCS_VMENTRY_INSTRUCTION_LENGTH, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tpr_threshold: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_TPR_THRESHOLD, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls: {
                    mut_ret = mut_intrinsic.vmwr32(
                        VMCS_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS, sanitize_proc2_ctls(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ple_gap: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_PLE_GAP, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ple_window: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_PLE_WINDOW, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vm_instruction_error: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_VM_INSTRUCTION_ERROR, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exit_reason: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_EXIT_REASON, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_interruption_information: {
                    mut_ret = mut_intrinsic.vmwr32(
                        VMCS_VMEXIT_INTERRUPTION_INFORMATION, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_interruption_error_code: {
                    mut_ret =
                        mut_intrinsic.vmwr32(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idt_vectoring_information_field: {
                    mut_ret = mut_intrinsic.vmwr32(
                        VMCS_IDT_VECTORING_INFORMATION_FIELD, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idt_vectoring_error_code: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_IDT_VECTORING_ERROR_CODE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_instruction_length: {
                    mut_ret =
                        mut_intrinsic.vmwr32(VMCS_VMEXIT_INSTRUCTION_LENGTH, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_instruction_information: {
                    mut_ret =
                        mut_intrinsic.vmwr32(VMCS_VMEXIT_INSTRUCTION_INFORMATION, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_limit: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_ES_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_limit: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_CS_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_limit: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_SS_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_limit: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_DS_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_limit: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_FS_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_limit: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_GS_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_limit: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_LDTR_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_limit: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_TR_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_limit: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_GDTR_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_limit: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_IDTR_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_attrib: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_ES_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_attrib: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_CS_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_attrib: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_SS_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_attrib: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_DS_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_attrib: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_FS_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_attrib: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_GS_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_attrib: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_LDTR_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_attrib: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_TR_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_interruptibility_state: {
                    mut_ret =
                        mut_intrinsic.vmwr32(VMCS_GUEST_INTERRUPTIBILITY_STATE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_activity_state: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_ACTIVITY_STATE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_smbase: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_SMBASE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_cs: {
                    mut_ret = mut_intrinsic.vmwr32(VMCS_GUEST_SYSENTER_CS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmx_preemption_timer_value: {
                    mut_ret =
                        mut_intrinsic.vmwr32(VMCS_VMX_PREEMPTION_TIMER_VALUE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0_guest_host_mask: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_CR0_GUEST_HOST_MASK, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4_guest_host_mask: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_CR4_GUEST_HOST_MASK, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0_read_shadow: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_CR0_READ_SHADOW, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4_read_shadow: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_CR4_READ_SHADOW, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value0: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_CR3_TARGET_VALUE0, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value1: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_CR3_TARGET_VALUE1, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value2: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_CR3_TARGET_VALUE2, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value3: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_CR3_TARGET_VALUE3, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exit_qualification: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_EXIT_QUALIFICATION, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rcx: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_IO_RCX, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rsi: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_IO_RSI, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rdi: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_IO_RDI, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rip: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_IO_RIP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_linear_address: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_LINEAR_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0: {
                    auto const sanitized{this->sanitize_cr0(bsl::to_u64(val))};
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_CR0, sanitized);
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_CR3, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4: {
                    auto const sanitized{this->sanitize_cr4(bsl::to_u64(val))};
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_CR4, sanitized);
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_es_base: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_ES_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cs_base: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_CS_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ss_base: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_SS_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ds_base: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_DS_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_fs_base: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_FS_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gs_base: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_GS_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ldtr_base: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_LDTR_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tr_base: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_TR_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_gdtr_base: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_GDTR_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idtr_base: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_IDTR_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_dr7: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_DR7, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rsp: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_RSP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rip: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_RIP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_rflags: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_RFLAGS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pending_debug_exceptions: {
                    mut_ret =
                        mut_intrinsic.vmwr64(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_esp: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_SYSENTER_ESP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_sysenter_eip: {
                    mut_ret = mut_intrinsic.vmwr64(VMCS_GUEST_SYSENTER_EIP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr8: {
                    m_missing_registers.guest_cr8 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr0: {
                    m_missing_registers.guest_dr0 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr1: {
                    m_missing_registers.guest_dr1 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr2: {
                    m_missing_registers.guest_dr2 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_dr3: {
                    m_missing_registers.guest_dr3 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_xcr0: {
                    m_missing_registers.guest_xcr0 = sanitize_xcr0(val).get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_invalid: {
                    bsl::error() << "invalid bf_reg_t\n" << bsl::here();
                    break;
                }
            }

            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Runs the vs_t. Note that this function does not
        ///     return until a VMExit occurs. Once complete, this function
        ///     will return the VMExit reason.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///   @param mut_log the VMExit log to use
        ///   @return Returns the VMExit reason on success, or
        ///     bsl::safe_umx::failure() on failure.
        ///
        [[nodiscard]] constexpr auto
        run(tls_t &mut_tls, intrinsic_t &mut_intrinsic, vmexit_log_t &mut_log) noexcept
            -> bsl::safe_umx
        {
            this->ensure_this_vs_is_loaded(mut_tls, mut_intrinsic);

            m_status = running_status_t::running;
            auto const exit_reason{mut_intrinsic.vmrun(&m_missing_registers)};
            m_status = running_status_t::handling_vmexit;

            if constexpr (BSL_DEBUG_LEVEL >= bsl::VV) {
                mut_log.add(
                    bsl::to_u16(mut_tls.ppid),
                    {bsl::to_u16(mut_tls.active_vmid),
                     bsl::to_u16(mut_tls.active_vpid),
                     bsl::to_u16(mut_tls.active_vsid),
                     exit_reason,
                     mut_intrinsic.vmrd64(VMCS_EXIT_QUALIFICATION),
                     mut_intrinsic.vmrd64(VMCS_VMEXIT_INSTRUCTION_INFORMATION),
                     {},
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RAX),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RBX),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RCX),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RDX),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RBP),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RSI),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_RDI),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R8),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R9),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R10),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R11),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R12),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R13),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R14),
                     mut_intrinsic.tls_reg(syscall::TLS_OFFSET_R15),
                     mut_intrinsic.vmrd64(VMCS_GUEST_RSP),
                     mut_intrinsic.vmrd64(VMCS_GUEST_RIP)});
            }

            return exit_reason;
        }

        /// <!-- description -->
        ///   @brief Advance the IP of the vs_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsic_t to use
        ///
        constexpr void
        advance_ip(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept
        {
            bsl::safe_u64 mut_rip{};
            bsl::safe_u64 mut_len{};

            this->ensure_this_vs_is_loaded(mut_tls, mut_intrinsic);

            bsl::expects(mut_intrinsic.vmrd64(VMCS_GUEST_RIP, mut_rip.data()));
            bsl::expects(mut_intrinsic.vmrd64(VMCS_VMEXIT_INSTRUCTION_LENGTH, mut_len.data()));

            auto const nrip{(mut_rip + mut_len).checked()};
            bsl::expects(mut_intrinsic.vmwr64(VMCS_GUEST_RIP, nrip));
        }

        /// <!-- description -->
        ///   @brief Clears the vs_t's internal cache. Note that this is a
        ///     hardware specific function and doesn't change the actual
        ///     values stored in the vs_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        clear(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::discard(intrinsic);
            bsl::expects(allocated_status_t::allocated == m_allocated);

            if (bsl::unlikely(running_status_t::running == m_status)) {
                bsl::error() << "vs "                                                 // --
                             << bsl::hex(this->id())                                  // --
                             << " is still running and cannot be cleared/migrated"    // --
                             << bsl::endl                                             // --
                             << bsl::here();                                          // --

                return bsl::errc_failure;
            }

            bsl::expects(intrinsic.vmcl(&m_vmcs_phys));
            m_missing_registers.launched = {};

            if (this->id() == mut_tls.loaded_vsid) {
                mut_tls.loaded_vsid = syscall::BF_INVALID_ID.get();
            }
            else {
                bsl::touch();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Flushes any TLB entries associated with this VS on
        ///     the current PP.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        tlb_flush(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept
        {
            this->ensure_this_vs_is_loaded(mut_tls, intrinsic);

            auto const vpid{intrinsic.vmrd16(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER)};
            intrinsic.tlb_flush({}, vpid);
        }

        /// <!-- description -->
        ///   @brief Given a GLA, invalidates any TLB entries on this PP
        ///     associated with this VS for the provided GLA.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///   @param gla the guest linear address to invalidate
        ///
        constexpr void
        tlb_flush(tls_t &mut_tls, intrinsic_t const &intrinsic, bsl::safe_u64 const &gla) noexcept
        {
            this->ensure_this_vs_is_loaded(mut_tls, intrinsic);

            auto const vpid{intrinsic.vmrd16(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER)};
            intrinsic.tlb_flush(gla, vpid);
        }

        /// <!-- description -->
        ///   @brief Dumps the vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        dump(tls_t &mut_tls, intrinsic_t const &intrinsic) const noexcept
        {
            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            this->ensure_this_vs_is_loaded(mut_tls, intrinsic);

            // clang-format off

            bsl::print() << bsl::mag << "vs [";
            bsl::print() << bsl::rst << bsl::hex(this->id());
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
            if (this->assigned_vp() != syscall::BF_INVALID_ID) {
                bsl::print() << bsl::grn << "      " << bsl::hex(this->assigned_vp()) << "       ";
            }
            else {
                bsl::print() << bsl::red << "      " << bsl::hex(this->assigned_vp()) << "       ";
            }
            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::endl;

            /// Assigned PP
            ///

            bsl::print() << bsl::ylw << "| ";
            bsl::print() << bsl::rst << bsl::fmt{"<40s", "assigned pp "};
            bsl::print() << bsl::ylw << "| ";
            if (this->assigned_pp() != syscall::BF_INVALID_ID) {
                bsl::print() << bsl::grn << "      " << bsl::hex(this->assigned_pp()) << "       ";
            }
            else {
                bsl::print() << bsl::red << "      " << bsl::hex(this->assigned_pp()) << "       ";
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

            if (mut_tls.active_vsid == this->id()) {
                this->dump_field("rax ", intrinsic.tls_reg(syscall::TLS_OFFSET_RAX));
                this->dump_field("rbx ", intrinsic.tls_reg(syscall::TLS_OFFSET_RBX));
                this->dump_field("rcx ", intrinsic.tls_reg(syscall::TLS_OFFSET_RCX));
                this->dump_field("rdx ", intrinsic.tls_reg(syscall::TLS_OFFSET_RDX));
                this->dump_field("rbp ", intrinsic.tls_reg(syscall::TLS_OFFSET_RBP));
                this->dump_field("rsi ", intrinsic.tls_reg(syscall::TLS_OFFSET_RSI));
                this->dump_field("rdi ", intrinsic.tls_reg(syscall::TLS_OFFSET_RDI));
                this->dump_field("r8 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R8));
                this->dump_field("r9 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R9));
                this->dump_field("r10 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R10));
                this->dump_field("r11 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R11));
                this->dump_field("r12 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R12));
                this->dump_field("r13 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R13));
                this->dump_field("r14 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R14));
                this->dump_field("r15 ", intrinsic.tls_reg(syscall::TLS_OFFSET_R15));
            }
            else {
                this->dump_field("rax ", bsl::make_safe(m_gprs.rax));
                this->dump_field("rbx ", bsl::make_safe(m_gprs.rbx));
                this->dump_field("rcx ", bsl::make_safe(m_gprs.rcx));
                this->dump_field("rdx ", bsl::make_safe(m_gprs.rdx));
                this->dump_field("rbp ", bsl::make_safe(m_gprs.rbp));
                this->dump_field("rsi ", bsl::make_safe(m_gprs.rsi));
                this->dump_field("rdi ", bsl::make_safe(m_gprs.rdi));
                this->dump_field("r8 ", bsl::make_safe(m_gprs.r8));
                this->dump_field("r9 ", bsl::make_safe(m_gprs.r9));
                this->dump_field("r10 ", bsl::make_safe(m_gprs.r10));
                this->dump_field("r11 ", bsl::make_safe(m_gprs.r11));
                this->dump_field("r12 ", bsl::make_safe(m_gprs.r12));
                this->dump_field("r13 ", bsl::make_safe(m_gprs.r13));
                this->dump_field("r14 ", bsl::make_safe(m_gprs.r14));
                this->dump_field("r15 ", bsl::make_safe(m_gprs.r15));
            }

            /// 16 Bit Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("virtual_processor_identifier ", intrinsic.vmrd16(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER));
            this->dump_field("posted_interrupt_notification_vector ", intrinsic.vmrd16(VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR));
            this->dump_field("eptp_index ", intrinsic.vmrd16(VMCS_EPTP_INDEX));

            /// 16 Bit Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("es_selector ", intrinsic.vmrd16(VMCS_GUEST_ES_SELECTOR));
            this->dump_field("cs_selector ", intrinsic.vmrd16(VMCS_GUEST_CS_SELECTOR));
            this->dump_field("ss_selector ", intrinsic.vmrd16(VMCS_GUEST_SS_SELECTOR));
            this->dump_field("ds_selector ", intrinsic.vmrd16(VMCS_GUEST_DS_SELECTOR));
            this->dump_field("fs_selector ", intrinsic.vmrd16(VMCS_GUEST_FS_SELECTOR));
            this->dump_field("gs_selector ", intrinsic.vmrd16(VMCS_GUEST_GS_SELECTOR));
            this->dump_field("ldtr_selector ", intrinsic.vmrd16(VMCS_GUEST_LDTR_SELECTOR));
            this->dump_field("tr_selector ", intrinsic.vmrd16(VMCS_GUEST_TR_SELECTOR));
            this->dump_field("interrupt_status ", intrinsic.vmrd16(VMCS_GUEST_INTERRUPT_STATUS));
            this->dump_field("pml_index ", intrinsic.vmrd16(VMCS_PML_INDEX));

            /// 64 Bit Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("address_of_io_bitmap_a ", intrinsic.vmrd64(VMCS_ADDRESS_OF_IO_BITMAP_A));
            this->dump_field("address_of_io_bitmap_b ", intrinsic.vmrd64(VMCS_ADDRESS_OF_IO_BITMAP_B));
            this->dump_field("address_of_msr_bitmaps ", intrinsic.vmrd64(VMCS_ADDRESS_OF_MSR_BITMAPS));
            this->dump_field("vmexit_msr_store_address ", intrinsic.vmrd64(VMCS_VMEXIT_MSR_STORE_ADDRESS));
            this->dump_field("vmexit_msr_load_address ", intrinsic.vmrd64(VMCS_VMEXIT_MSR_LOAD_ADDRESS));
            this->dump_field("vmentry_msr_load_address ", intrinsic.vmrd64(VMCS_VMENTRY_MSR_LOAD_ADDRESS));
            this->dump_field("executive_vmcs_pointer ", intrinsic.vmrd64(VMCS_EXECUTIVE_VMCS_POINTER));
            this->dump_field("pml_address ", intrinsic.vmrd64(VMCS_PML_ADDRESS));
            this->dump_field("tsc_offset ", intrinsic.vmrd64(VMCS_TSC_OFFSET));
            this->dump_field("virtual_apic_address ", intrinsic.vmrd64(VMCS_VIRTUAL_APIC_ADDRESS));
            this->dump_field("apic_access_address ", intrinsic.vmrd64(VMCS_APIC_ACCESS_ADDRESS));
            this->dump_field("posted_interrupt_descriptor_address ", intrinsic.vmrd64(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS));
            this->dump_field("vm_function_controls ", intrinsic.vmrd64(VMCS_VM_FUNCTION_CONTROLS));
            this->dump_field("ept_pointer ", intrinsic.vmrd64(VMCS_EPT_POINTER));
            this->dump_field("eoi_exit_bitmap0 ", intrinsic.vmrd64(VMCS_EOI_EXIT_BITMAP0));
            this->dump_field("eoi_exit_bitmap1 ", intrinsic.vmrd64(VMCS_EOI_EXIT_BITMAP1));
            this->dump_field("eoi_exit_bitmap2 ", intrinsic.vmrd64(VMCS_EOI_EXIT_BITMAP2));
            this->dump_field("eoi_exit_bitmap3 ", intrinsic.vmrd64(VMCS_EOI_EXIT_BITMAP3));
            this->dump_field("eptp_list_address ", intrinsic.vmrd64(VMCS_EPTP_LIST_ADDRESS));
            this->dump_field("vmrd_bitmap_address ", intrinsic.vmrd64(VMCS_VMREAD_BITMAP_ADDRESS));
            this->dump_field("vmwr_bitmap_address ", intrinsic.vmrd64(VMCS_VMWRITE_BITMAP_ADDRESS));
            this->dump_field("virt_exception_information_address ", intrinsic.vmrd64(VMCS_VIRT_EXCEPTION_INFORMATION_ADDRESS));
            this->dump_field("xss_exiting_bitmap ", intrinsic.vmrd64(VMCS_XSS_EXITING_BITMAP));
            this->dump_field("encls_exiting_bitmap ", intrinsic.vmrd64(VMCS_ENCLS_EXITING_BITMAP));
            this->dump_field("sub_page_permission_table_pointer ", intrinsic.vmrd64(VMCS_SUB_PAGE_PERMISSION_TABLE_POINTER));
            this->dump_field("tls_multiplier ", intrinsic.vmrd64(VMCS_TLS_MULTIPLIER));

            /// 64 Bit Read-Only Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("guest_physical_address ", intrinsic.vmrd64(VMCS_GUEST_PHYSICAL_ADDRESS));

            /// 64 Bit Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("vmcs_link_pointer ", intrinsic.vmrd64(VMCS_VMCS_LINK_POINTER));
            this->dump_field("debugctl ", intrinsic.vmrd64(VMCS_GUEST_DEBUGCTL));
            this->dump_field("pat ", intrinsic.vmrd64(VMCS_GUEST_PAT));
            this->dump_field("efer ", intrinsic.vmrd64(VMCS_GUEST_EFER));
            this->dump_field("perf_global_ctrl ", intrinsic.vmrd64(VMCS_GUEST_PERF_GLOBAL_CTRL));
            this->dump_field("guest_pdpte0 ", intrinsic.vmrd64(VMCS_GUEST_PDPTE0));
            this->dump_field("guest_pdpte1 ", intrinsic.vmrd64(VMCS_GUEST_PDPTE1));
            this->dump_field("guest_pdpte2 ", intrinsic.vmrd64(VMCS_GUEST_PDPTE2));
            this->dump_field("guest_pdpte3 ", intrinsic.vmrd64(VMCS_GUEST_PDPTE3));
            this->dump_field("bndcfgs ", intrinsic.vmrd64(VMCS_GUEST_BNDCFGS));
            this->dump_field("guest_rtit_ctl ", intrinsic.vmrd64(VMCS_GUEST_RTIT_CTL));
            this->dump_field("star ", bsl::make_safe(m_missing_registers.guest_star));
            this->dump_field("lstar ", bsl::make_safe(m_missing_registers.guest_lstar));
            this->dump_field("cstar ", bsl::make_safe(m_missing_registers.guest_cstar));
            this->dump_field("fmask ", bsl::make_safe(m_missing_registers.guest_fmask));
            this->dump_field("kernel_gs_base ", bsl::make_safe(m_missing_registers.guest_kernel_gs_base));

            /// 32 Bit Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("pin_based_vm_execution_ctls ", intrinsic.vmrd32(VMCS_PIN_BASED_VM_EXECUTION_CTLS));
            this->dump_field("primary_proc_based_vm_execution_ctls ", intrinsic.vmrd32(VMCS_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS));
            this->dump_field("exception_bitmap ", intrinsic.vmrd32(VMCS_EXCEPTION_BITMAP));
            this->dump_field("page_fault_error_code_mask ", intrinsic.vmrd32(VMCS_PAGE_FAULT_ERROR_CODE_MASK));
            this->dump_field("page_fault_error_code_match ", intrinsic.vmrd32(VMCS_PAGE_FAULT_ERROR_CODE_MATCH));
            this->dump_field("cr3_target_count ", intrinsic.vmrd32(VMCS_CR3_TARGET_COUNT));
            this->dump_field("vmexit_ctls ", intrinsic.vmrd32(VMCS_VMEXIT_CTLS));
            this->dump_field("vmexit_msr_store_count ", intrinsic.vmrd32(VMCS_VMEXIT_MSR_STORE_COUNT));
            this->dump_field("vmexit_msr_load_count ", intrinsic.vmrd32(VMCS_VMEXIT_MSR_LOAD_COUNT));
            this->dump_field("vmentry_ctls ", intrinsic.vmrd32(VMCS_VMENTRY_CTLS));
            this->dump_field("vmentry_msr_load_count ", intrinsic.vmrd32(VMCS_VMENTRY_MSR_LOAD_COUNT));
            this->dump_field("vmentry_interrupt_information_field ", intrinsic.vmrd32(VMCS_VMENTRY_INTERRUPT_INFORMATION_FIELD));
            this->dump_field("vmentry_exception_error_code ", intrinsic.vmrd32(VMCS_VMENTRY_EXCEPTION_ERROR_CODE));
            this->dump_field("vmentry_instruction_length ", intrinsic.vmrd32(VMCS_VMENTRY_INSTRUCTION_LENGTH));
            this->dump_field("tpr_threshold ", intrinsic.vmrd32(VMCS_TPR_THRESHOLD));
            this->dump_field("secondary_proc_based_vm_execution_ctls ", intrinsic.vmrd32(VMCS_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS));
            this->dump_field("ple_gap ", intrinsic.vmrd32(VMCS_PLE_GAP));
            this->dump_field("ple_window ", intrinsic.vmrd32(VMCS_PLE_WINDOW));

            /// 32 Bit Read-Only Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("exit_reason ", intrinsic.vmrd32(VMCS_EXIT_REASON));
            this->dump_field("vmexit_interruption_information ", intrinsic.vmrd32(VMCS_VMEXIT_INTERRUPTION_INFORMATION));
            this->dump_field("vmexit_interruption_error_code ", intrinsic.vmrd32(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE));
            this->dump_field("idt_vectoring_information_field ", intrinsic.vmrd32(VMCS_IDT_VECTORING_INFORMATION_FIELD));
            this->dump_field("idt_vectoring_error_code ", intrinsic.vmrd32(VMCS_IDT_VECTORING_ERROR_CODE));
            this->dump_field("vmexit_instruction_length ", intrinsic.vmrd32(VMCS_VMEXIT_INSTRUCTION_LENGTH));
            this->dump_field("vmexit_instruction_information ", intrinsic.vmrd32(VMCS_VMEXIT_INSTRUCTION_INFORMATION));

            /// 32 Bit Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("es_limit ", intrinsic.vmrd32(VMCS_GUEST_ES_LIMIT));
            this->dump_field("cs_limit ", intrinsic.vmrd32(VMCS_GUEST_CS_LIMIT));
            this->dump_field("ss_limit ", intrinsic.vmrd32(VMCS_GUEST_SS_LIMIT));
            this->dump_field("ds_limit ", intrinsic.vmrd32(VMCS_GUEST_DS_LIMIT));
            this->dump_field("fs_limit ", intrinsic.vmrd32(VMCS_GUEST_FS_LIMIT));
            this->dump_field("gs_limit ", intrinsic.vmrd32(VMCS_GUEST_GS_LIMIT));
            this->dump_field("ldtr_limit ", intrinsic.vmrd32(VMCS_GUEST_LDTR_LIMIT));
            this->dump_field("tr_limit ", intrinsic.vmrd32(VMCS_GUEST_TR_LIMIT));
            this->dump_field("gdtr_limit ", intrinsic.vmrd32(VMCS_GUEST_GDTR_LIMIT));
            this->dump_field("idtr_limit ", intrinsic.vmrd32(VMCS_GUEST_IDTR_LIMIT));
            this->dump_field("es_attrib ", intrinsic.vmrd32(VMCS_GUEST_ES_ACCESS_RIGHTS));
            this->dump_field("cs_attrib ", intrinsic.vmrd32(VMCS_GUEST_CS_ACCESS_RIGHTS));
            this->dump_field("ss_attrib ", intrinsic.vmrd32(VMCS_GUEST_SS_ACCESS_RIGHTS));
            this->dump_field("ds_attrib ", intrinsic.vmrd32(VMCS_GUEST_DS_ACCESS_RIGHTS));
            this->dump_field("fs_attrib ", intrinsic.vmrd32(VMCS_GUEST_FS_ACCESS_RIGHTS));
            this->dump_field("gs_attrib ", intrinsic.vmrd32(VMCS_GUEST_GS_ACCESS_RIGHTS));
            this->dump_field("ldtr_attrib ", intrinsic.vmrd32(VMCS_GUEST_LDTR_ACCESS_RIGHTS));
            this->dump_field("tr_attrib ", intrinsic.vmrd32(VMCS_GUEST_TR_ACCESS_RIGHTS));
            this->dump_field("guest_interruptibility_state ", intrinsic.vmrd32(VMCS_GUEST_INTERRUPTIBILITY_STATE));
            this->dump_field("guest_activity_state ", intrinsic.vmrd32(VMCS_GUEST_ACTIVITY_STATE));
            this->dump_field("guest_smbase ", intrinsic.vmrd32(VMCS_GUEST_SMBASE));
            this->dump_field("sysenter_cs ", intrinsic.vmrd32(VMCS_GUEST_SYSENTER_CS));
            this->dump_field("vmx_preemption_timer_value ", intrinsic.vmrd32(VMCS_VMX_PREEMPTION_TIMER_VALUE));

            /// Natural-Width Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("cr0_guest_host_mask ", intrinsic.vmrd64(VMCS_CR0_GUEST_HOST_MASK));
            this->dump_field("cr4_guest_host_mask ", intrinsic.vmrd64(VMCS_CR4_GUEST_HOST_MASK));
            this->dump_field("cr0_read_shadow ", intrinsic.vmrd64(VMCS_CR0_READ_SHADOW));
            this->dump_field("cr4_read_shadow ", intrinsic.vmrd64(VMCS_CR4_READ_SHADOW));
            this->dump_field("cr3_target_value0 ", intrinsic.vmrd64(VMCS_CR3_TARGET_VALUE0));
            this->dump_field("cr3_target_value1 ", intrinsic.vmrd64(VMCS_CR3_TARGET_VALUE1));
            this->dump_field("cr3_target_value2 ", intrinsic.vmrd64(VMCS_CR3_TARGET_VALUE2));
            this->dump_field("cr3_target_value3 ", intrinsic.vmrd64(VMCS_CR3_TARGET_VALUE3));

            /// Natural-Width Read-Only Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("exit_qualification ", intrinsic.vmrd64(VMCS_EXIT_QUALIFICATION));
            this->dump_field("io_rcx ", intrinsic.vmrd64(VMCS_IO_RCX));
            this->dump_field("io_rsi ", intrinsic.vmrd64(VMCS_IO_RSI));
            this->dump_field("io_rdi ", intrinsic.vmrd64(VMCS_IO_RDI));
            this->dump_field("io_rip ", intrinsic.vmrd64(VMCS_IO_RIP));
            this->dump_field("guest_linear_address ", intrinsic.vmrd64(VMCS_GUEST_LINEAR_ADDRESS));

            /// Natural-Width Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("cr0 ", intrinsic.vmrd64(VMCS_GUEST_CR0));
            this->dump_field("cr2 ", bsl::make_safe(m_missing_registers.guest_cr2));
            this->dump_field("cr3 ", intrinsic.vmrd64(VMCS_GUEST_CR3));
            this->dump_field("cr4 ", intrinsic.vmrd64(VMCS_GUEST_CR4));
            this->dump_field("cr8 ", bsl::make_safe(m_missing_registers.guest_cr8));
            this->dump_field("xcr0 ", bsl::make_safe(m_missing_registers.guest_xcr0));
            this->dump_field("es_base ", intrinsic.vmrd64(VMCS_GUEST_ES_BASE));
            this->dump_field("cs_base ", intrinsic.vmrd64(VMCS_GUEST_CS_BASE));
            this->dump_field("ss_base ", intrinsic.vmrd64(VMCS_GUEST_SS_BASE));
            this->dump_field("ds_base ", intrinsic.vmrd64(VMCS_GUEST_DS_BASE));
            this->dump_field("fs_base ", intrinsic.vmrd64(VMCS_GUEST_FS_BASE));
            this->dump_field("gs_base ", intrinsic.vmrd64(VMCS_GUEST_GS_BASE));
            this->dump_field("ldtr_base ", intrinsic.vmrd64(VMCS_GUEST_LDTR_BASE));
            this->dump_field("tr_base ", intrinsic.vmrd64(VMCS_GUEST_TR_BASE));
            this->dump_field("gdtr_base ", intrinsic.vmrd64(VMCS_GUEST_GDTR_BASE));
            this->dump_field("idtr_base ", intrinsic.vmrd64(VMCS_GUEST_IDTR_BASE));
            this->dump_field("dr0 ", bsl::make_safe(m_missing_registers.guest_dr0));
            this->dump_field("dr1 ", bsl::make_safe(m_missing_registers.guest_dr1));
            this->dump_field("dr2 ", bsl::make_safe(m_missing_registers.guest_dr2));
            this->dump_field("dr3 ", bsl::make_safe(m_missing_registers.guest_dr3));
            this->dump_field("dr6 ", bsl::make_safe(m_missing_registers.guest_dr6));
            this->dump_field("dr7 ", intrinsic.vmrd64(VMCS_GUEST_DR7));
            this->dump_field("rsp ", intrinsic.vmrd64(VMCS_GUEST_RSP));
            this->dump_field("rip ", intrinsic.vmrd64(VMCS_GUEST_RIP));
            this->dump_field("rflags ", intrinsic.vmrd64(VMCS_GUEST_RFLAGS));
            this->dump_field("guest_pending_debug_exceptions ", intrinsic.vmrd64(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS));
            this->dump_field("sysenter_esp ", intrinsic.vmrd64(VMCS_GUEST_SYSENTER_ESP));
            this->dump_field("sysenter_eip ", intrinsic.vmrd64(VMCS_GUEST_SYSENTER_EIP));

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            // clang-format on
        }
    };
}

#endif
