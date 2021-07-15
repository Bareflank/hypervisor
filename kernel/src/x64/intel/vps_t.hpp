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

        /// <!-- description -->
        ///   @brief Stores the provided ES segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param selector_idx the selector VMCS index to use
        ///   @param selector_val the selector value to write to the VMCS
        ///   @param attrib_idx the attrib VMCS index to use
        ///   @param attrib_val the attrib value to write to the VMCS
        ///   @param limit_idx the limit VMCS index to use
        ///   @param limit_val the limit value to write to the VMCS
        ///   @param base_idx the base VMCS index to use
        ///   @param base_val the base value to write to the VMCS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        set_segment_descriptor(
            intrinsic_t &mut_intrinsic,
            bsl::safe_uintmax const &selector_idx,
            bsl::safe_uint16 const &selector_val,
            bsl::safe_uintmax const &attrib_idx,
            bsl::safe_uint32 const &attrib_val,
            bsl::safe_uintmax const &limit_idx,
            bsl::safe_uint32 const &limit_val,
            bsl::safe_uintmax const &base_idx,
            bsl::safe_uint64 const &base_val) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            if (selector_val.is_zero()) {
                mut_ret = mut_intrinsic.vmwrite16(selector_idx, {});
                if (bsl::unlikely_assert(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                mut_ret = mut_intrinsic.vmwrite32(attrib_idx, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely_assert(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                mut_ret = mut_intrinsic.vmwrite32(limit_idx, {});
                if (bsl::unlikely_assert(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                mut_ret = mut_intrinsic.vmwrite64(base_idx, {});
                if (bsl::unlikely_assert(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                bsl::touch();
            }
            else {
                mut_ret = mut_intrinsic.vmwrite16(selector_idx, selector_val);
                if (bsl::unlikely_assert(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                mut_ret = mut_intrinsic.vmwrite32(attrib_idx, attrib_val);
                if (bsl::unlikely_assert(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                mut_ret = mut_intrinsic.vmwrite32(limit_idx, limit_val);
                if (bsl::unlikely_assert(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                mut_ret = mut_intrinsic.vmwrite64(base_idx, base_val);
                if (bsl::unlikely_assert(!mut_ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return mut_ret;
                }

                bsl::touch();
            }

            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Stores the ES segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param selector_idx the selector VMCS index to use
        ///   @param pmut_selector_val the selector value to read from the VMCS
        ///   @param attrib_idx the attrib VMCS index to use
        ///   @param pmut_attrib_val the attrib value to read from the VMCS
        ///   @param limit_idx the limit VMCS index to use
        ///   @param pmut_limit_val the limit value to read from the VMCS
        ///   @param base_idx the base VMCS index to use
        ///   @param pmut_base_val the base value to read from the VMCS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        get_segment_descriptor(
            intrinsic_t const &intrinsic,
            bsl::safe_uintmax const &selector_idx,
            bsl::uint16 *const pmut_selector_val,
            bsl::safe_uintmax const &attrib_idx,
            bsl::uint16 *const pmut_attrib_val,
            bsl::safe_uintmax const &limit_idx,
            bsl::uint32 *const pmut_limit_val,
            bsl::safe_uintmax const &base_idx,
            bsl::uint64 *const pmut_base_val) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};
            bsl::safe_uint32 mut_attrib{};

            mut_ret = intrinsic.vmread16(selector_idx, pmut_selector_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread32(attrib_idx, mut_attrib.data());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread32(limit_idx, pmut_limit_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(base_idx, pmut_base_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            if (VMCS_UNUSABLE_SEGMENT == mut_attrib) {
                *pmut_selector_val = {};
                *pmut_attrib_val = {};
                *pmut_limit_val = {};
                *pmut_base_val = {};
            }
            else {
                *pmut_attrib_val = bsl::to_u16(mut_attrib).get();
            }

            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of the provided pinbased_ctls
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of the provided pinbased_ctls
        ///
        [[nodiscard]] static constexpr auto
        sanitize_pinbased_ctls(bsl::safe_uint64 const &val) noexcept -> bsl::safe_uint32
        {
            constexpr auto vmcs_pinbased_ctls_mask{0x28_u64};
            return bsl::to_u32(val | vmcs_pinbased_ctls_mask);
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of the provided exit_ctls
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of the provided exit_ctls
        ///
        [[nodiscard]] static constexpr auto
        sanitize_exit_ctls(bsl::safe_uint64 const &val) noexcept -> bsl::safe_uint32
        {
            constexpr auto vmcs_exit_ctls_mask{0x3C0204_u64};
            return bsl::to_u32(val | vmcs_exit_ctls_mask);
        }

        /// <!-- description -->
        ///   @brief Returns a sanitized version of the provided entry_ctls
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to sanitize
        ///   @return Returns a sanitized version of the provided entry_ctls
        ///
        [[nodiscard]] static constexpr auto
        sanitize_entry_ctls(bsl::safe_uint64 const &val) noexcept -> bsl::safe_uint32
        {
            constexpr auto vmcs_entry_ctls_mask{0xC204_u64};
            return bsl::to_u32(val | vmcs_entry_ctls_mask);
        }

        /// <!-- description -->
        ///   @brief Ensures that this VPS is loaded
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        ensure_this_vps_is_loaded(tls_t &mut_tls, intrinsic_t const &intrinsic) const noexcept
            -> bsl::errc_type
        {
            if (m_id == mut_tls.loaded_vpsid) {
                return bsl::errc_success;
            }

            auto const ret{intrinsic.vmload(&m_vmcs_phys)};
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            mut_tls.loaded_vpsid = m_id.get();
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
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        init_vmcs(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};
            auto *const pmut_state{mut_tls.mk_state};

            auto const revision_id{mut_intrinsic.rdmsr(IA32_VMX_BASIC)};
            if (bsl::unlikely_assert(!revision_id)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_vmcs->revision_id = bsl::to_u32_unsafe(revision_id).get();

            mut_ret = this->ensure_this_vps_is_loaded(mut_tls, mut_intrinsic);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite16(VMCS_HOST_ES_SELECTOR, mut_intrinsic.es_selector());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite16(VMCS_HOST_CS_SELECTOR, mut_intrinsic.cs_selector());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite16(VMCS_HOST_SS_SELECTOR, mut_intrinsic.ss_selector());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite16(VMCS_HOST_DS_SELECTOR, mut_intrinsic.ds_selector());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite16(VMCS_HOST_FS_SELECTOR, mut_intrinsic.fs_selector());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite16(VMCS_HOST_GS_SELECTOR, mut_intrinsic.gs_selector());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite16(VMCS_HOST_TR_SELECTOR, mut_intrinsic.tr_selector());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_HOST_IA32_PAT, mut_intrinsic.rdmsr(IA32_PAT));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_HOST_IA32_EFER, mut_intrinsic.rdmsr(IA32_EFER));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(
                VMCS_HOST_IA32_SYSENTER_CS, mut_intrinsic.rdmsr(IA32_SYSENTER_CS));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_HOST_CR0, mut_intrinsic.cr0());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_HOST_CR3, mut_intrinsic.cr3());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_HOST_CR4, mut_intrinsic.cr4());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_HOST_FS_BASE, mut_intrinsic.rdmsr(IA32_FS_BASE));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_HOST_GS_BASE, mut_intrinsic.rdmsr(IA32_GS_BASE));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_HOST_TR_BASE, bsl::to_u64(pmut_state->tr_base));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret =
                mut_intrinsic.vmwrite64(VMCS_HOST_GDTR_BASE, bsl::to_u64(pmut_state->gdtr.base));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret =
                mut_intrinsic.vmwrite64(VMCS_HOST_IDTR_BASE, bsl::to_u64(pmut_state->idtr.base));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(
                VMCS_HOST_IA32_SYSENTER_ESP, mut_intrinsic.rdmsr(IA32_SYSENTER_ESP));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(
                VMCS_HOST_IA32_SYSENTER_EIP, mut_intrinsic.rdmsr(IA32_SYSENTER_EIP));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwritefunc(VMCS_HOST_RIP, &intrinsic_vmexit);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            m_vmcs_missing_registers.host_ia32_star =              // --
                mut_intrinsic.rdmsr(IA32_STAR).get();              // --
            m_vmcs_missing_registers.host_ia32_lstar =             // --
                mut_intrinsic.rdmsr(IA32_LSTAR).get();             // --
            m_vmcs_missing_registers.host_ia32_cstar =             // --
                mut_intrinsic.rdmsr(IA32_CSTAR).get();             // --
            m_vmcs_missing_registers.host_ia32_fmask =             // --
                mut_intrinsic.rdmsr(IA32_FMASK).get();             // --
            m_vmcs_missing_registers.host_ia32_kernel_gs_base =    // --
                mut_intrinsic.rdmsr(IA32_KERNEL_GS_BASE).get();    // --

            return mut_ret;
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
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        release(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept -> bsl::errc_type
        {
            if (this->is_zombie()) {
                return bsl::errc_success;
            }

            bsl::finally mut_zombify_on_error{[this]() noexcept -> void {
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
            mut_page_pool.deallocate(mut_tls, m_vmcs, ALLOCATE_TAG_VMCS);
            m_vmcs = {};

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vpid = syscall::BF_INVALID_ID;
            m_allocated = allocated_status_t::deallocated;
            m_id = bsl::safe_uint16::failure();

            mut_zombify_on_error.ignore();
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
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param mut_page_pool the page pool to use
        ///   @param vpid The ID of the VP to assign the newly created VP to
        ///   @param ppid The ID of the PP to assign the newly created VP to
        ///   @return Returns ID of the newly allocated vps
        ///
        [[nodiscard]] constexpr auto
        allocate(
            tls_t &mut_tls,
            intrinsic_t &mut_intrinsic,
            page_pool_t &mut_page_pool,
            bsl::safe_uint16 const &vpid,
            bsl::safe_uint16 const &ppid) noexcept -> bsl::safe_uint16
        {
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

            // if (bsl::unlikely(vp_pool.is_zombie(mut_tls, vpid))) {
            //     bsl::error() << "vp "                                                // --
            //                  << bsl::hex(vpid)                                       // --
            //                  << " is a zombie and a vps cannot be assigned to it"    // --
            //                  << bsl::endl                                            // --
            //                  << bsl::here();                                         // --

            //     return bsl::safe_uint16::failure();
            // }

            // if (bsl::unlikely(vp_pool.is_deallocated(mut_tls, vpid))) {
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

            if (bsl::unlikely(!(ppid < mut_tls.online_pps))) {
                bsl::error() << "pp "                                                  // --
                             << bsl::hex(ppid)                                         // --
                             << " is not less than the total number of online pps "    // --
                             << bsl::hex(mut_tls.online_pps)                           // --
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

            bsl::finally mut_cleanup_on_error{[this, &mut_tls, &mut_page_pool]() noexcept -> void {
                m_vmcs_phys = bsl::safe_uintmax::failure();
                mut_page_pool.deallocate(mut_tls, m_vmcs, ALLOCATE_TAG_VMCS);
                m_vmcs = {};
            }};

            m_vmcs = mut_page_pool.template allocate<vmcs_t>(mut_tls, ALLOCATE_TAG_VMCS);
            if (bsl::unlikely(nullptr == m_vmcs)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            m_vmcs_phys = mut_page_pool.virt_to_phys(m_vmcs);
            if (bsl::unlikely_assert(!m_vmcs_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            auto const ret{this->init_vmcs(mut_tls, mut_intrinsic)};
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uint16::failure();
            }

            m_assigned_vpid = vpid;
            m_assigned_ppid = ppid;
            m_allocated = allocated_status_t::allocated;

            mut_cleanup_on_error.ignore();
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Deallocates this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_page_pool the page pool to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        deallocate(tls_t &mut_tls, page_pool_t &mut_page_pool) noexcept -> bsl::errc_type
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

            bsl::finally mut_zombify_on_error{[this]() noexcept -> void {
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
            mut_page_pool.deallocate(mut_tls, m_vmcs, ALLOCATE_TAG_VMCS);
            m_vmcs = {};

            m_assigned_ppid = syscall::BF_INVALID_ID;
            m_assigned_vpid = syscall::BF_INVALID_ID;
            m_allocated = allocated_status_t::deallocated;

            mut_zombify_on_error.ignore();
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
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_active(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept -> bsl::errc_type
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

            if (bsl::unlikely(mut_tls.active_vpid != m_assigned_vpid)) {
                bsl::error() << "vps "                                 // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to vp "                  // --
                             << bsl::hex(m_assigned_vpid)              // --
                             << " and cannot be activated with vp "    // --
                             << bsl::hex(mut_tls.active_vpid)          // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely(mut_tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vps "                               // --
                             << bsl::hex(m_id)                       // --
                             << " is assigned to pp "                // --
                             << bsl::hex(m_assigned_ppid)            // --
                             << " and cannot be activated on pp "    // --
                             << bsl::hex(mut_tls.ppid)               // --
                             << bsl::endl                            // --
                             << bsl::here();                         // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID != mut_tls.active_vpsid)) {
                bsl::error() << "vps "                            // --
                             << bsl::hex(mut_tls.active_vpsid)    // --
                             << " is still active on pp "         // --
                             << bsl::hex(mut_tls.ppid)            // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

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

            mut_tls.active_vpsid = m_id.get();
            m_active_ppid = mut_tls.ppid;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets this vps_t as inactive.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set_inactive(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
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

            if (bsl::unlikely_assert(syscall::BF_INVALID_ID == mut_tls.active_vpsid)) {
                bsl::error() << "vps "                     // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(mut_tls.ppid)     // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_precondition;
            }

            if (bsl::unlikely_assert(mut_tls.active_vpsid != m_id)) {
                bsl::error() << "vps "                            // --
                             << bsl::hex(mut_tls.active_vpsid)    // --
                             << " is still active on pp "         // --
                             << bsl::hex(mut_tls.ppid)            // --
                             << bsl::endl                         // --
                             << bsl::here();                      // --

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

            if (bsl::unlikely_assert(mut_tls.ppid != m_active_ppid)) {
                bsl::error() << "vps "                     // --
                             << bsl::hex(m_id)             // --
                             << " is not active on pp "    // --
                             << bsl::hex(mut_tls.ppid)     // --
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

            mut_tls.active_vpsid = syscall::BF_INVALID_ID.get();
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
        is_active(tls_t const &tls) const noexcept -> bsl::safe_uint16
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
        is_active_on_current_pp(tls_t const &tls) const noexcept -> bool
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
        migrate(
            tls_t const &tls, intrinsic_t const &intrinsic, bsl::safe_uint16 const &ppid) noexcept
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
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        [[nodiscard]] constexpr auto
        state_save_to_vps(
            tls_t &mut_tls, intrinsic_t &mut_intrinsic, loader::state_save_t const &state) noexcept
            -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

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

            if (bsl::unlikely(mut_tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(mut_tls.ppid)                 // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            mut_ret = this->ensure_this_vps_is_loaded(mut_tls, mut_intrinsic);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            if (mut_tls.active_vpsid == m_id) {
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, bsl::to_u64(state.rax));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, bsl::to_u64(state.rbx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, bsl::to_u64(state.rcx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, bsl::to_u64(state.rdx));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, bsl::to_u64(state.rbp));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, bsl::to_u64(state.rsi));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, bsl::to_u64(state.rdi));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, bsl::to_u64(state.r8));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, bsl::to_u64(state.r9));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, bsl::to_u64(state.r10));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, bsl::to_u64(state.r11));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, bsl::to_u64(state.r12));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, bsl::to_u64(state.r13));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, bsl::to_u64(state.r14));
                mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, bsl::to_u64(state.r15));
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

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_RSP, bsl::to_u64(state.rsp));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_RIP, bsl::to_u64(state.rip));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_RFLAGS, bsl::to_u64(state.rflags));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            auto const gdtr_limit{bsl::to_u32(state.gdtr.limit)};
            mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_GDTR_LIMIT, gdtr_limit);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_GDTR_BASE, bsl::to_u64(state.gdtr.base));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            auto const idtr_limit{bsl::to_u32(state.idtr.limit)};
            mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_IDTR_LIMIT, idtr_limit);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_IDTR_BASE, bsl::to_u64(state.idtr.base));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_ES_SELECTOR,
                bsl::to_u16(state.es_selector),
                VMCS_GUEST_ES_ACCESS_RIGHTS,
                bsl::to_u32(state.es_attrib),
                VMCS_GUEST_ES_LIMIT,
                bsl::to_u32(state.es_limit),
                VMCS_GUEST_ES_BASE,
                bsl::to_u64(state.es_base));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_CS_SELECTOR,
                bsl::to_u16(state.cs_selector),
                VMCS_GUEST_CS_ACCESS_RIGHTS,
                bsl::to_u32(state.cs_attrib),
                VMCS_GUEST_CS_LIMIT,
                bsl::to_u32(state.cs_limit),
                VMCS_GUEST_CS_BASE,
                bsl::to_u64(state.cs_base));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_SS_SELECTOR,
                bsl::to_u16(state.ss_selector),
                VMCS_GUEST_SS_ACCESS_RIGHTS,
                bsl::to_u32(state.ss_attrib),
                VMCS_GUEST_SS_LIMIT,
                bsl::to_u32(state.ss_limit),
                VMCS_GUEST_SS_BASE,
                bsl::to_u64(state.ss_base));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_DS_SELECTOR,
                bsl::to_u16(state.ds_selector),
                VMCS_GUEST_DS_ACCESS_RIGHTS,
                bsl::to_u32(state.ds_attrib),
                VMCS_GUEST_DS_LIMIT,
                bsl::to_u32(state.ds_limit),
                VMCS_GUEST_DS_BASE,
                bsl::to_u64(state.ds_base));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_FS_SELECTOR,
                bsl::to_u16(state.fs_selector),
                VMCS_GUEST_FS_ACCESS_RIGHTS,
                bsl::to_u32(state.fs_attrib),
                VMCS_GUEST_FS_LIMIT,
                bsl::to_u32(state.fs_limit),
                VMCS_GUEST_FS_BASE,
                bsl::to_u64(state.fs_base));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_GS_SELECTOR,
                bsl::to_u16(state.gs_selector),
                VMCS_GUEST_GS_ACCESS_RIGHTS,
                bsl::to_u32(state.gs_attrib),
                VMCS_GUEST_GS_LIMIT,
                bsl::to_u32(state.gs_limit),
                VMCS_GUEST_GS_BASE,
                bsl::to_u64(state.gs_base));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_LDTR_SELECTOR,
                bsl::to_u16(state.ldtr_selector),
                VMCS_GUEST_LDTR_ACCESS_RIGHTS,
                bsl::to_u32(state.ldtr_attrib),
                VMCS_GUEST_LDTR_LIMIT,
                bsl::to_u32(state.ldtr_limit),
                VMCS_GUEST_LDTR_BASE,
                bsl::to_u64(state.ldtr_base));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->set_segment_descriptor(
                mut_intrinsic,
                VMCS_GUEST_TR_SELECTOR,
                bsl::to_u16(state.tr_selector),
                VMCS_GUEST_TR_ACCESS_RIGHTS,
                bsl::to_u32(state.tr_attrib),
                VMCS_GUEST_TR_LIMIT,
                bsl::to_u32(state.tr_limit),
                VMCS_GUEST_TR_BASE,
                bsl::to_u64(state.tr_base));

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_CR0, bsl::to_u64(state.cr0));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            m_vmcs_missing_registers.guest_cr2 = state.cr2;

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_CR3, bsl::to_u64(state.cr3));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_CR4, bsl::to_u64(state.cr4));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            m_vmcs_missing_registers.guest_dr6 = state.dr6;

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_DR7, bsl::to_u64(state.dr7));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_IA32_EFER, bsl::to_u64(state.ia32_efer));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            m_vmcs_missing_registers.guest_ia32_star = state.ia32_star;
            m_vmcs_missing_registers.guest_ia32_lstar = state.ia32_lstar;
            m_vmcs_missing_registers.guest_ia32_cstar = state.ia32_cstar;
            m_vmcs_missing_registers.guest_ia32_fmask = state.ia32_fmask;

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_FS_BASE, bsl::to_u64(state.ia32_fs_base));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_GS_BASE, bsl::to_u64(state.ia32_gs_base));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            m_vmcs_missing_registers.guest_ia32_kernel_gs_base = state.ia32_kernel_gs_base;

            mut_ret = mut_intrinsic.vmwrite64(
                VMCS_GUEST_IA32_SYSENTER_CS, bsl::to_u64(state.ia32_sysenter_cs));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(
                VMCS_GUEST_IA32_SYSENTER_ESP, bsl::to_u64(state.ia32_sysenter_esp));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(
                VMCS_GUEST_IA32_SYSENTER_EIP, bsl::to_u64(state.ia32_sysenter_eip));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_IA32_PAT, bsl::to_u64(state.ia32_pat));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret =
                mut_intrinsic.vmwrite64(VMCS_GUEST_IA32_DEBUGCTL, bsl::to_u64(state.ia32_debugctl));
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Stores the VPS state in the provided state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param mut_state the state save to store the VPS state to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        [[nodiscard]] constexpr auto
        vps_to_state_save(
            tls_t &mut_tls,
            intrinsic_t const &intrinsic,
            loader::state_save_t &mut_state) const noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

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

            if (bsl::unlikely(mut_tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(mut_tls.ppid)                 // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            mut_ret = this->ensure_this_vps_is_loaded(mut_tls, intrinsic);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            if (mut_tls.active_vpsid == m_id) {
                mut_state.rax = intrinsic.tls_reg(syscall::TLS_OFFSET_RAX).get();
                mut_state.rbx = intrinsic.tls_reg(syscall::TLS_OFFSET_RBX).get();
                mut_state.rcx = intrinsic.tls_reg(syscall::TLS_OFFSET_RCX).get();
                mut_state.rdx = intrinsic.tls_reg(syscall::TLS_OFFSET_RDX).get();
                mut_state.rbp = intrinsic.tls_reg(syscall::TLS_OFFSET_RBP).get();
                mut_state.rsi = intrinsic.tls_reg(syscall::TLS_OFFSET_RSI).get();
                mut_state.rdi = intrinsic.tls_reg(syscall::TLS_OFFSET_RDI).get();
                mut_state.r8 = intrinsic.tls_reg(syscall::TLS_OFFSET_R8).get();
                mut_state.r9 = intrinsic.tls_reg(syscall::TLS_OFFSET_R9).get();
                mut_state.r10 = intrinsic.tls_reg(syscall::TLS_OFFSET_R10).get();
                mut_state.r11 = intrinsic.tls_reg(syscall::TLS_OFFSET_R11).get();
                mut_state.r12 = intrinsic.tls_reg(syscall::TLS_OFFSET_R12).get();
                mut_state.r13 = intrinsic.tls_reg(syscall::TLS_OFFSET_R13).get();
                mut_state.r14 = intrinsic.tls_reg(syscall::TLS_OFFSET_R14).get();
                mut_state.r15 = intrinsic.tls_reg(syscall::TLS_OFFSET_R15).get();
            }
            else {
                mut_state.rax = m_gprs.rax;
                mut_state.rbx = m_gprs.rbx;
                mut_state.rcx = m_gprs.rcx;
                mut_state.rdx = m_gprs.rdx;
                mut_state.rbp = m_gprs.rbp;
                mut_state.rsi = m_gprs.rsi;
                mut_state.rdi = m_gprs.rdi;
                mut_state.r8 = m_gprs.r8;
                mut_state.r9 = m_gprs.r9;
                mut_state.r10 = m_gprs.r10;
                mut_state.r11 = m_gprs.r11;
                mut_state.r12 = m_gprs.r12;
                mut_state.r13 = m_gprs.r13;
                mut_state.r14 = m_gprs.r14;
                mut_state.r15 = m_gprs.r15;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_RSP, &mut_state.rsp);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_RIP, &mut_state.rip);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_RFLAGS, &mut_state.rflags);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread16(VMCS_GUEST_GDTR_LIMIT, &mut_state.gdtr.limit);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_GDTR_BASE, &mut_state.gdtr.base);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread16(VMCS_GUEST_IDTR_LIMIT, &mut_state.idtr.limit);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_IDTR_BASE, &mut_state.idtr.base);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_ES_SELECTOR,
                &mut_state.es_selector,
                VMCS_GUEST_ES_ACCESS_RIGHTS,
                &mut_state.es_attrib,
                VMCS_GUEST_ES_LIMIT,
                &mut_state.es_limit,
                VMCS_GUEST_ES_BASE,
                &mut_state.es_base);

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_CS_SELECTOR,
                &mut_state.cs_selector,
                VMCS_GUEST_CS_ACCESS_RIGHTS,
                &mut_state.cs_attrib,
                VMCS_GUEST_CS_LIMIT,
                &mut_state.cs_limit,
                VMCS_GUEST_CS_BASE,
                &mut_state.cs_base);

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_SS_SELECTOR,
                &mut_state.ss_selector,
                VMCS_GUEST_SS_ACCESS_RIGHTS,
                &mut_state.ss_attrib,
                VMCS_GUEST_SS_LIMIT,
                &mut_state.ss_limit,
                VMCS_GUEST_SS_BASE,
                &mut_state.ss_base);

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_DS_SELECTOR,
                &mut_state.ds_selector,
                VMCS_GUEST_DS_ACCESS_RIGHTS,
                &mut_state.ds_attrib,
                VMCS_GUEST_DS_LIMIT,
                &mut_state.ds_limit,
                VMCS_GUEST_DS_BASE,
                &mut_state.ds_base);

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_FS_SELECTOR,
                &mut_state.fs_selector,
                VMCS_GUEST_FS_ACCESS_RIGHTS,
                &mut_state.fs_attrib,
                VMCS_GUEST_FS_LIMIT,
                &mut_state.fs_limit,
                VMCS_GUEST_FS_BASE,
                &mut_state.fs_base);

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_GS_SELECTOR,
                &mut_state.gs_selector,
                VMCS_GUEST_GS_ACCESS_RIGHTS,
                &mut_state.gs_attrib,
                VMCS_GUEST_GS_LIMIT,
                &mut_state.gs_limit,
                VMCS_GUEST_GS_BASE,
                &mut_state.gs_base);

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_LDTR_SELECTOR,
                &mut_state.ldtr_selector,
                VMCS_GUEST_LDTR_ACCESS_RIGHTS,
                &mut_state.ldtr_attrib,
                VMCS_GUEST_LDTR_LIMIT,
                &mut_state.ldtr_limit,
                VMCS_GUEST_LDTR_BASE,
                &mut_state.ldtr_base);

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = this->get_segment_descriptor(
                intrinsic,
                VMCS_GUEST_TR_SELECTOR,
                &mut_state.tr_selector,
                VMCS_GUEST_TR_ACCESS_RIGHTS,
                &mut_state.tr_attrib,
                VMCS_GUEST_TR_LIMIT,
                &mut_state.tr_limit,
                VMCS_GUEST_TR_BASE,
                &mut_state.tr_base);

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_CR0, &mut_state.cr0);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_state.cr2 = m_vmcs_missing_registers.guest_cr2;

            mut_ret = intrinsic.vmread64(VMCS_GUEST_CR3, &mut_state.cr3);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_CR4, &mut_state.cr4);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_state.dr6 = m_vmcs_missing_registers.guest_dr6;

            mut_ret = intrinsic.vmread64(VMCS_GUEST_DR7, &mut_state.dr7);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_EFER, &mut_state.ia32_efer);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_state.ia32_star = m_vmcs_missing_registers.guest_ia32_star;
            mut_state.ia32_lstar = m_vmcs_missing_registers.guest_ia32_lstar;
            mut_state.ia32_cstar = m_vmcs_missing_registers.guest_ia32_cstar;
            mut_state.ia32_fmask = m_vmcs_missing_registers.guest_ia32_fmask;

            mut_ret = intrinsic.vmread64(VMCS_GUEST_FS_BASE, &mut_state.ia32_fs_base);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_GS_BASE, &mut_state.ia32_gs_base);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_state.ia32_kernel_gs_base = m_vmcs_missing_registers.guest_ia32_kernel_gs_base;

            mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_SYSENTER_CS, &mut_state.ia32_sysenter_cs);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret =
                intrinsic.vmread64(VMCS_GUEST_IA32_SYSENTER_ESP, &mut_state.ia32_sysenter_esp);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret =
                intrinsic.vmread64(VMCS_GUEST_IA32_SYSENTER_EIP, &mut_state.ia32_sysenter_eip);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_PAT, &mut_state.ia32_pat);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_DEBUGCTL, &mut_state.ia32_debugctl);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Reads a field from the VPS given a bf_reg_t
        ///     defining the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @param reg a bf_reg_t defining the field to read from the VPS
        ///   @return Returns the value of the requested field from the
        ///     VPS or bsl::safe_uintmax::failure() on failure.
        [[nodiscard]] constexpr auto
        read(tls_t &mut_tls, intrinsic_t const &intrinsic, syscall::bf_reg_t const reg)
            const noexcept -> bsl::safe_uintmax
        {
            bsl::errc_type mut_ret{};
            bsl::safe_uint64 mut_val{};

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

            if (bsl::unlikely(mut_tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(mut_tls.ppid)                 // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::safe_uintmax::failure();
            }

            mut_ret = this->ensure_this_vps_is_loaded(mut_tls, intrinsic);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_rax: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RAX);
                    }

                    return bsl::to_u64(m_gprs.rax);
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RBX);
                    }

                    return bsl::to_u64(m_gprs.rbx);
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RCX);
                    }

                    return bsl::to_u64(m_gprs.rcx);
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RDX);
                    }

                    return bsl::to_u64(m_gprs.rdx);
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RBP);
                    }

                    return bsl::to_u64(m_gprs.rbp);
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RSI);
                    }

                    return bsl::to_u64(m_gprs.rsi);
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_RDI);
                    }

                    return bsl::to_u64(m_gprs.rdi);
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R8);
                    }

                    return bsl::to_u64(m_gprs.r8);
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R9);
                    }

                    return bsl::to_u64(m_gprs.r9);
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R10);
                    }

                    return bsl::to_u64(m_gprs.r10);
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R11);
                    }

                    return bsl::to_u64(m_gprs.r11);
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R12);
                    }

                    return bsl::to_u64(m_gprs.r12);
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R13);
                    }

                    return bsl::to_u64(m_gprs.r13);
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R14);
                    }

                    return bsl::to_u64(m_gprs.r14);
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    if (mut_tls.active_vpsid == m_id) {
                        return intrinsic.tls_reg(syscall::TLS_OFFSET_R15);
                    }

                    return bsl::to_u64(m_gprs.r15);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cr2: {
                    return bsl::to_u64(m_vmcs_missing_registers.guest_cr2);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_dr6: {
                    return bsl::to_u64(m_vmcs_missing_registers.guest_dr6);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_star: {
                    return bsl::to_u64(m_vmcs_missing_registers.guest_ia32_star);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_lstar: {
                    return bsl::to_u64(m_vmcs_missing_registers.guest_ia32_lstar);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_cstar: {
                    return bsl::to_u64(m_vmcs_missing_registers.guest_ia32_cstar);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_fmask: {
                    return bsl::to_u64(m_vmcs_missing_registers.guest_ia32_fmask);
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_kernel_gs_base: {
                    return bsl::to_u64(m_vmcs_missing_registers.guest_ia32_kernel_gs_base);
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier: {
                    mut_ret = intrinsic.vmread64(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_posted_interrupt_notification_vector: {
                    mut_ret = intrinsic.vmread64(
                        VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eptp_index: {
                    mut_ret = intrinsic.vmread64(VMCS_EPTP_INDEX, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_es_selector: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_ES_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cs_selector: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_CS_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ss_selector: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_SS_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ds_selector: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_DS_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_fs_selector: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_FS_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gs_selector: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_GS_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ldtr_selector: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_LDTR_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_tr_selector: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_TR_SELECTOR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_interrupt_status: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_INTERRUPT_STATUS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pml_index: {
                    mut_ret = intrinsic.vmread64(VMCS_PML_INDEX, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_io_bitmap_a: {
                    mut_ret = intrinsic.vmread64(VMCS_ADDRESS_OF_IO_BITMAP_A, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_io_bitmap_b: {
                    mut_ret = intrinsic.vmread64(VMCS_ADDRESS_OF_IO_BITMAP_B, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_msr_bitmaps: {
                    mut_ret = intrinsic.vmread64(VMCS_ADDRESS_OF_MSR_BITMAPS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_store_address: {
                    mut_ret = intrinsic.vmread64(VMCS_VMEXIT_MSR_STORE_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_load_address: {
                    mut_ret = intrinsic.vmread64(VMCS_VMEXIT_MSR_LOAD_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_msr_load_address: {
                    mut_ret = intrinsic.vmread64(VMCS_VMENTRY_MSR_LOAD_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_executive_vmcs_pointer: {
                    mut_ret = intrinsic.vmread64(VMCS_EXECUTIVE_VMCS_POINTER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pml_address: {
                    mut_ret = intrinsic.vmread64(VMCS_PML_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tsc_offset: {
                    mut_ret = intrinsic.vmread64(VMCS_TSC_OFFSET, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_apic_address: {
                    mut_ret = intrinsic.vmread64(VMCS_VIRTUAL_APIC_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_apic_access_address: {
                    mut_ret = intrinsic.vmread64(VMCS_APIC_ACCESS_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_posted_interrupt_descriptor_address: {
                    mut_ret = intrinsic.vmread64(
                        VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vm_function_controls: {
                    mut_ret = intrinsic.vmread64(VMCS_VM_FUNCTION_CONTROLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ept_pointer: {
                    mut_ret = intrinsic.vmread64(VMCS_EPT_POINTER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap0: {
                    mut_ret = intrinsic.vmread64(VMCS_EOI_EXIT_BITMAP0, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap1: {
                    mut_ret = intrinsic.vmread64(VMCS_EOI_EXIT_BITMAP1, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap2: {
                    mut_ret = intrinsic.vmread64(VMCS_EOI_EXIT_BITMAP2, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap3: {
                    mut_ret = intrinsic.vmread64(VMCS_EOI_EXIT_BITMAP3, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eptp_list_address: {
                    mut_ret = intrinsic.vmread64(VMCS_EPTP_LIST_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmread_bitmap_address: {
                    mut_ret = intrinsic.vmread64(VMCS_VMREAD_BITMAP_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmwrite_bitmap_address: {
                    mut_ret = intrinsic.vmread64(VMCS_VMWRITE_BITMAP_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_virt_exception_information_address: {
                    mut_ret =
                        intrinsic.vmread64(VMCS_VIRT_EXCEPTION_INFORMATION_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_xss_exiting_bitmap: {
                    mut_ret = intrinsic.vmread64(VMCS_XSS_EXITING_BITMAP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_encls_exiting_bitmap: {
                    mut_ret = intrinsic.vmread64(VMCS_ENCLS_EXITING_BITMAP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_sub_page_permission_table_pointer: {
                    mut_ret =
                        intrinsic.vmread64(VMCS_SUB_PAGE_PERMISSION_TABLE_POINTER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tls_multiplier: {
                    mut_ret = intrinsic.vmread64(VMCS_TLS_MULTIPLIER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_physical_address: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_PHYSICAL_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer: {
                    mut_ret = intrinsic.vmread64(VMCS_VMCS_LINK_POINTER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_debugctl: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_DEBUGCTL, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_pat: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_PAT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_efer: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_EFER, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_perf_global_ctrl: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pdpte0: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_PDPTE0, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pdpte1: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_PDPTE1, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pdpte2: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_PDPTE2, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pdpte3: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_PDPTE3, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_bndcfgs: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_BNDCFGS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_rtit_ctl: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_RTIT_CTL, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls: {
                    mut_ret = intrinsic.vmread64(VMCS_PIN_BASED_VM_EXECUTION_CTLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls: {
                    mut_ret = intrinsic.vmread64(
                        VMCS_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exception_bitmap: {
                    mut_ret = intrinsic.vmread64(VMCS_EXCEPTION_BITMAP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_page_fault_error_code_mask: {
                    mut_ret = intrinsic.vmread64(VMCS_PAGE_FAULT_ERROR_CODE_MASK, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_page_fault_error_code_match: {
                    mut_ret = intrinsic.vmread64(VMCS_PAGE_FAULT_ERROR_CODE_MATCH, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_count: {
                    mut_ret = intrinsic.vmread64(VMCS_CR3_TARGET_COUNT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_ctls: {
                    mut_ret = intrinsic.vmread64(VMCS_VMEXIT_CTLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_store_count: {
                    mut_ret = intrinsic.vmread64(VMCS_VMEXIT_MSR_STORE_COUNT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_load_count: {
                    mut_ret = intrinsic.vmread64(VMCS_VMEXIT_MSR_LOAD_COUNT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_ctls: {
                    mut_ret = intrinsic.vmread64(VMCS_VMENTRY_CTLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_msr_load_count: {
                    mut_ret = intrinsic.vmread64(VMCS_VMENTRY_MSR_LOAD_COUNT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_interrupt_information_field: {
                    mut_ret = intrinsic.vmread64(
                        VMCS_VMENTRY_INTERRUPT_INFORMATION_FIELD, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_exception_error_code: {
                    mut_ret = intrinsic.vmread64(VMCS_VMENTRY_EXCEPTION_ERROR_CODE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_instruction_length: {
                    mut_ret = intrinsic.vmread64(VMCS_VMENTRY_INSTRUCTION_LENGTH, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tpr_threshold: {
                    mut_ret = intrinsic.vmread64(VMCS_TPR_THRESHOLD, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls: {
                    mut_ret = intrinsic.vmread64(
                        VMCS_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ple_gap: {
                    mut_ret = intrinsic.vmread64(VMCS_PLE_GAP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ple_window: {
                    mut_ret = intrinsic.vmread64(VMCS_PLE_WINDOW, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vm_instruction_error: {
                    mut_ret = intrinsic.vmread64(VMCS_VM_INSTRUCTION_ERROR, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exit_reason: {
                    mut_ret = intrinsic.vmread64(VMCS_EXIT_REASON, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_interruption_information: {
                    mut_ret =
                        intrinsic.vmread64(VMCS_VMEXIT_INTERRUPTION_INFORMATION, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_interruption_error_code: {
                    mut_ret =
                        intrinsic.vmread64(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idt_vectoring_information_field: {
                    mut_ret =
                        intrinsic.vmread64(VMCS_IDT_VECTORING_INFORMATION_FIELD, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idt_vectoring_error_code: {
                    mut_ret = intrinsic.vmread64(VMCS_IDT_VECTORING_ERROR_CODE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_instruction_length: {
                    mut_ret = intrinsic.vmread64(VMCS_VMEXIT_INSTRUCTION_LENGTH, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_instruction_information: {
                    mut_ret =
                        intrinsic.vmread64(VMCS_VMEXIT_INSTRUCTION_INFORMATION, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_es_limit: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_ES_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cs_limit: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_CS_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ss_limit: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_SS_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ds_limit: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_DS_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_fs_limit: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_FS_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gs_limit: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_GS_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ldtr_limit: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_LDTR_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_tr_limit: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_TR_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gdtr_limit: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_GDTR_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_idtr_limit: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_IDTR_LIMIT, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_es_access_rights: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_ES_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cs_access_rights: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_CS_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ss_access_rights: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_SS_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ds_access_rights: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_DS_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_fs_access_rights: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_FS_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gs_access_rights: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_GS_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ldtr_access_rights: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_LDTR_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_tr_access_rights: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_TR_ACCESS_RIGHTS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_interruptibility_state: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_INTERRUPTIBILITY_STATE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_activity_state: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_ACTIVITY_STATE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_smbase: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_SMBASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_sysenter_cs: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_SYSENTER_CS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmx_preemption_timer_value: {
                    mut_ret = intrinsic.vmread64(VMCS_VMX_PREEMPTION_TIMER_VALUE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0_guest_host_mask: {
                    mut_ret = intrinsic.vmread64(VMCS_CR0_GUEST_HOST_MASK, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4_guest_host_mask: {
                    mut_ret = intrinsic.vmread64(VMCS_CR4_GUEST_HOST_MASK, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0_read_shadow: {
                    mut_ret = intrinsic.vmread64(VMCS_CR0_READ_SHADOW, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4_read_shadow: {
                    mut_ret = intrinsic.vmread64(VMCS_CR4_READ_SHADOW, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value0: {
                    mut_ret = intrinsic.vmread64(VMCS_CR3_TARGET_VALUE0, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value1: {
                    mut_ret = intrinsic.vmread64(VMCS_CR3_TARGET_VALUE1, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value2: {
                    mut_ret = intrinsic.vmread64(VMCS_CR3_TARGET_VALUE2, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value3: {
                    mut_ret = intrinsic.vmread64(VMCS_CR3_TARGET_VALUE3, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exit_qualification: {
                    mut_ret = intrinsic.vmread64(VMCS_EXIT_QUALIFICATION, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rcx: {
                    mut_ret = intrinsic.vmread64(VMCS_IO_RCX, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rsi: {
                    mut_ret = intrinsic.vmread64(VMCS_IO_RSI, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rdi: {
                    mut_ret = intrinsic.vmread64(VMCS_IO_RDI, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rip: {
                    mut_ret = intrinsic.vmread64(VMCS_IO_RIP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_linear_address: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_LINEAR_ADDRESS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cr0: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_CR0, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cr3: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_CR3, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cr4: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_CR4, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_es_base: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_ES_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cs_base: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_CS_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ss_base: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_SS_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ds_base: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_DS_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_fs_base: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_FS_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gs_base: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_GS_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ldtr_base: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_LDTR_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_tr_base: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_TR_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gdtr_base: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_GDTR_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_idtr_base: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_IDTR_BASE, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_dr7: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_DR7, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_rsp: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_RSP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_rip: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_RIP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_rflags: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_RFLAGS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pending_debug_exceptions: {
                    mut_ret =
                        intrinsic.vmread64(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_sysenter_esp: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_SYSENTER_ESP, mut_val.data());
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_sysenter_eip: {
                    mut_ret = intrinsic.vmread64(VMCS_GUEST_IA32_SYSENTER_EIP, mut_val.data());
                    break;
                }

                default: {
                    mut_ret = bsl::errc_failure;
                    bsl::error() << "unknown by bf_reg_t\n" << bsl::here();
                    break;
                }
            }

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uintmax::failure();
            }

            return mut_val;
        }

        /// <!-- description -->
        ///   @brief Writes a field to the VPS given a bf_reg_t
        ///     defining the field and a value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param reg a bf_reg_t defining the field to write to the VPS
        ///   @param val the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///
        [[nodiscard]] constexpr auto
        write(
            tls_t &mut_tls,
            intrinsic_t &mut_intrinsic,
            syscall::bf_reg_t const reg,
            bsl::safe_uintmax const &val) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

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

            if (bsl::unlikely(mut_tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(mut_tls.ppid)                 // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            mut_ret = this->ensure_this_vps_is_loaded(mut_tls, mut_intrinsic);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_rax: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RAX, val);
                    }
                    else {
                        m_gprs.rax = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBX, val);
                    }
                    else {
                        m_gprs.rbx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RCX, val);
                    }
                    else {
                        m_gprs.rcx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDX, val);
                    }
                    else {
                        m_gprs.rdx = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RBP, val);
                    }
                    else {
                        m_gprs.rbp = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RSI, val);
                    }
                    else {
                        m_gprs.rsi = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_RDI, val);
                    }
                    else {
                        m_gprs.rdi = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R8, val);
                    }
                    else {
                        m_gprs.r8 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R9, val);
                    }
                    else {
                        m_gprs.r9 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R10, val);
                    }
                    else {
                        m_gprs.r10 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R11, val);
                    }
                    else {
                        m_gprs.r11 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R12, val);
                    }
                    else {
                        m_gprs.r12 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R13, val);
                    }
                    else {
                        m_gprs.r13 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R14, val);
                    }
                    else {
                        m_gprs.r14 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    if (mut_tls.active_vpsid == m_id) {
                        mut_intrinsic.set_tls_reg(syscall::TLS_OFFSET_R15, val);
                    }
                    else {
                        m_gprs.r15 = val.get();
                    }
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cr2: {
                    m_vmcs_missing_registers.guest_cr2 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_dr6: {
                    m_vmcs_missing_registers.guest_dr6 = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_star: {
                    m_vmcs_missing_registers.guest_ia32_star = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_lstar: {
                    m_vmcs_missing_registers.guest_ia32_lstar = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_cstar: {
                    m_vmcs_missing_registers.guest_ia32_cstar = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_fmask: {
                    m_vmcs_missing_registers.guest_ia32_fmask = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_kernel_gs_base: {
                    m_vmcs_missing_registers.guest_ia32_kernel_gs_base = val.get();
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_processor_identifier: {
                    mut_ret = mut_intrinsic.vmwrite16(
                        VMCS_VIRTUAL_PROCESSOR_IDENTIFIER, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_posted_interrupt_notification_vector: {
                    mut_ret = mut_intrinsic.vmwrite16(
                        VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eptp_index: {
                    mut_ret = mut_intrinsic.vmwrite16(VMCS_EPTP_INDEX, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_es_selector: {
                    mut_ret = mut_intrinsic.vmwrite16(VMCS_GUEST_ES_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cs_selector: {
                    mut_ret = mut_intrinsic.vmwrite16(VMCS_GUEST_CS_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ss_selector: {
                    mut_ret = mut_intrinsic.vmwrite16(VMCS_GUEST_SS_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ds_selector: {
                    mut_ret = mut_intrinsic.vmwrite16(VMCS_GUEST_DS_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_fs_selector: {
                    mut_ret = mut_intrinsic.vmwrite16(VMCS_GUEST_FS_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gs_selector: {
                    mut_ret = mut_intrinsic.vmwrite16(VMCS_GUEST_GS_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ldtr_selector: {
                    mut_ret = mut_intrinsic.vmwrite16(VMCS_GUEST_LDTR_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_tr_selector: {
                    mut_ret = mut_intrinsic.vmwrite16(VMCS_GUEST_TR_SELECTOR, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_interrupt_status: {
                    mut_ret =
                        mut_intrinsic.vmwrite16(VMCS_GUEST_INTERRUPT_STATUS, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pml_index: {
                    mut_ret = mut_intrinsic.vmwrite16(VMCS_PML_INDEX, bsl::to_u16(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_io_bitmap_a: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_ADDRESS_OF_IO_BITMAP_A, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_io_bitmap_b: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_ADDRESS_OF_IO_BITMAP_B, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_address_of_msr_bitmaps: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_ADDRESS_OF_MSR_BITMAPS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_store_address: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_VMEXIT_MSR_STORE_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_load_address: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_VMEXIT_MSR_LOAD_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_msr_load_address: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_VMENTRY_MSR_LOAD_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_executive_vmcs_pointer: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_EXECUTIVE_VMCS_POINTER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pml_address: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_PML_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tsc_offset: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_TSC_OFFSET, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_virtual_apic_address: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_VIRTUAL_APIC_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_apic_access_address: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_APIC_ACCESS_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_posted_interrupt_descriptor_address: {
                    mut_ret = mut_intrinsic.vmwrite64(
                        VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vm_function_controls: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_VM_FUNCTION_CONTROLS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ept_pointer: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_EPT_POINTER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap0: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_EOI_EXIT_BITMAP0, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap1: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_EOI_EXIT_BITMAP1, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap2: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_EOI_EXIT_BITMAP2, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eoi_exit_bitmap3: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_EOI_EXIT_BITMAP3, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_eptp_list_address: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_EPTP_LIST_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmread_bitmap_address: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_VMREAD_BITMAP_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmwrite_bitmap_address: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_VMWRITE_BITMAP_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_virt_exception_information_address: {
                    mut_ret = mut_intrinsic.vmwrite64(
                        VMCS_VIRT_EXCEPTION_INFORMATION_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_xss_exiting_bitmap: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_XSS_EXITING_BITMAP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_encls_exiting_bitmap: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_ENCLS_EXITING_BITMAP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_sub_page_permission_table_pointer: {
                    mut_ret = mut_intrinsic.vmwrite64(
                        VMCS_SUB_PAGE_PERMISSION_TABLE_POINTER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tls_multiplier: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_TLS_MULTIPLIER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_physical_address: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_GUEST_PHYSICAL_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmcs_link_pointer: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_VMCS_LINK_POINTER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_debugctl: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_IA32_DEBUGCTL, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_pat: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_IA32_PAT, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_efer: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_IA32_EFER, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_perf_global_ctrl: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pdpte0: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_PDPTE0, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pdpte1: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_PDPTE1, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pdpte2: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_PDPTE2, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pdpte3: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_PDPTE3, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_bndcfgs: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_IA32_BNDCFGS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_rtit_ctl: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_RTIT_CTL, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_pin_based_vm_execution_ctls: {
                    mut_ret = mut_intrinsic.vmwrite32(
                        VMCS_PIN_BASED_VM_EXECUTION_CTLS, sanitize_pinbased_ctls(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls: {
                    mut_ret = mut_intrinsic.vmwrite32(
                        VMCS_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exception_bitmap: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_EXCEPTION_BITMAP, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_page_fault_error_code_mask: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_PAGE_FAULT_ERROR_CODE_MASK, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_page_fault_error_code_match: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_PAGE_FAULT_ERROR_CODE_MATCH, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_count: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_CR3_TARGET_COUNT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_ctls: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_VMEXIT_CTLS, sanitize_exit_ctls(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_store_count: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_VMEXIT_MSR_STORE_COUNT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_msr_load_count: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_VMEXIT_MSR_LOAD_COUNT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_ctls: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_VMENTRY_CTLS, sanitize_entry_ctls(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_msr_load_count: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_VMENTRY_MSR_LOAD_COUNT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_interrupt_information_field: {
                    mut_ret = mut_intrinsic.vmwrite32(
                        VMCS_VMENTRY_INTERRUPT_INFORMATION_FIELD, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_exception_error_code: {
                    mut_ret = mut_intrinsic.vmwrite32(
                        VMCS_VMENTRY_EXCEPTION_ERROR_CODE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmentry_instruction_length: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_VMENTRY_INSTRUCTION_LENGTH, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_tpr_threshold: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_TPR_THRESHOLD, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_secondary_proc_based_vm_execution_ctls: {
                    mut_ret = mut_intrinsic.vmwrite32(
                        VMCS_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ple_gap: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_PLE_GAP, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_ple_window: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_PLE_WINDOW, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vm_instruction_error: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_VM_INSTRUCTION_ERROR, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exit_reason: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_EXIT_REASON, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_interruption_information: {
                    mut_ret = mut_intrinsic.vmwrite32(
                        VMCS_VMEXIT_INTERRUPTION_INFORMATION, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_interruption_error_code: {
                    mut_ret = mut_intrinsic.vmwrite32(
                        VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idt_vectoring_information_field: {
                    mut_ret = mut_intrinsic.vmwrite32(
                        VMCS_IDT_VECTORING_INFORMATION_FIELD, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_idt_vectoring_error_code: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_IDT_VECTORING_ERROR_CODE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_instruction_length: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_VMEXIT_INSTRUCTION_LENGTH, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmexit_instruction_information: {
                    mut_ret = mut_intrinsic.vmwrite32(
                        VMCS_VMEXIT_INSTRUCTION_INFORMATION, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_es_limit: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_ES_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cs_limit: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_CS_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ss_limit: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_SS_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ds_limit: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_DS_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_fs_limit: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_FS_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gs_limit: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_GS_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ldtr_limit: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_LDTR_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_tr_limit: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_TR_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gdtr_limit: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_GDTR_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_idtr_limit: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_IDTR_LIMIT, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_es_access_rights: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_GUEST_ES_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cs_access_rights: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_GUEST_CS_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ss_access_rights: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_GUEST_SS_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ds_access_rights: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_GUEST_DS_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_fs_access_rights: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_GUEST_FS_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gs_access_rights: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_GUEST_GS_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ldtr_access_rights: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_GUEST_LDTR_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_tr_access_rights: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_GUEST_TR_ACCESS_RIGHTS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_interruptibility_state: {
                    mut_ret = mut_intrinsic.vmwrite32(
                        VMCS_GUEST_INTERRUPTIBILITY_STATE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_activity_state: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_ACTIVITY_STATE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_smbase: {
                    mut_ret = mut_intrinsic.vmwrite32(VMCS_GUEST_SMBASE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_sysenter_cs: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_GUEST_IA32_SYSENTER_CS, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_vmx_preemption_timer_value: {
                    mut_ret =
                        mut_intrinsic.vmwrite32(VMCS_VMX_PREEMPTION_TIMER_VALUE, bsl::to_u32(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0_guest_host_mask: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_CR0_GUEST_HOST_MASK, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4_guest_host_mask: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_CR4_GUEST_HOST_MASK, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr0_read_shadow: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_CR0_READ_SHADOW, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr4_read_shadow: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_CR4_READ_SHADOW, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value0: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_CR3_TARGET_VALUE0, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value1: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_CR3_TARGET_VALUE1, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value2: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_CR3_TARGET_VALUE2, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_cr3_target_value3: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_CR3_TARGET_VALUE3, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_exit_qualification: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_EXIT_QUALIFICATION, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rcx: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_IO_RCX, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rsi: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_IO_RSI, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rdi: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_IO_RDI, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_io_rip: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_IO_RIP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_linear_address: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_LINEAR_ADDRESS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cr0: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_CR0, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cr3: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_CR3, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cr4: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_CR4, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_es_base: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_ES_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_cs_base: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_CS_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ss_base: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_SS_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ds_base: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_DS_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_fs_base: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_FS_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gs_base: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_GS_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ldtr_base: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_LDTR_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_tr_base: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_TR_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_gdtr_base: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_GDTR_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_idtr_base: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_IDTR_BASE, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_dr7: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_DR7, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_rsp: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_RSP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_rip: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_RIP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_rflags: {
                    mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_RFLAGS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_pending_debug_exceptions: {
                    mut_ret = mut_intrinsic.vmwrite64(
                        VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_sysenter_esp: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_GUEST_IA32_SYSENTER_ESP, bsl::to_u64(val));
                    break;
                }

                case syscall::bf_reg_t::bf_reg_t_guest_ia32_sysenter_eip: {
                    mut_ret =
                        mut_intrinsic.vmwrite64(VMCS_GUEST_IA32_SYSENTER_EIP, bsl::to_u64(val));
                    break;
                }

                default: {
                    mut_ret = bsl::errc_failure;
                    bsl::error() << "unknown by bf_reg_t\n" << bsl::here();
                    break;
                }
            }

            if (bsl::unlikely(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Runs the VPS. Note that this function does not
        ///     return until a VMExit occurs. Once complete, this function
        ///     will return the VMExit reason.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @param mut_log the VMExit log to use
        ///   @return Returns the VMExit reason on success, or
        ///
        [[nodiscard]] constexpr auto
        run(tls_t &mut_tls, intrinsic_t &mut_intrinsic, vmexit_log_t &mut_log) noexcept
            -> bsl::safe_uintmax
        {
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

            if (bsl::unlikely_assert(mut_tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                        // --
                             << bsl::hex(m_id)               // --
                             << " is assigned to pp "        // --
                             << bsl::hex(m_assigned_ppid)    // --
                             << " and cannot run by pp "     // --
                             << bsl::hex(mut_tls.ppid)       // --
                             << bsl::endl                    // --
                             << bsl::here();                 // --

                return bsl::safe_uintmax::failure();
            }

            auto const ret{this->ensure_this_vps_is_loaded(mut_tls, mut_intrinsic)};
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

            if constexpr (BSL_DEBUG_LEVEL >= bsl::VV) {
                mut_log.add(
                    bsl::to_u16(mut_tls.ppid),
                    {bsl::to_u16(mut_tls.active_vmid),
                     bsl::to_u16(mut_tls.active_vpid),
                     bsl::to_u16(mut_tls.active_vpsid),
                     exit_reason,
                     mut_intrinsic.vmread64_quiet(VMCS_EXIT_QUALIFICATION),
                     mut_intrinsic.vmread64_quiet(VMCS_VMEXIT_INSTRUCTION_INFORMATION),
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
                     mut_intrinsic.vmread64_quiet(VMCS_GUEST_RSP),
                     mut_intrinsic.vmread64_quiet(VMCS_GUEST_RIP)});
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
        ///   @param mut_tls the current TLS block
        ///   @param mut_intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        advance_ip(tls_t &mut_tls, intrinsic_t &mut_intrinsic) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};
            bsl::safe_uint64 mut_rip{};
            bsl::safe_uint64 mut_len{};

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

            if (bsl::unlikely(mut_tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(mut_tls.ppid)                 // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            mut_ret = this->ensure_this_vps_is_loaded(mut_tls, mut_intrinsic);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmread64(VMCS_GUEST_RIP, mut_rip.data());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmread64(VMCS_VMEXIT_INSTRUCTION_LENGTH, mut_len.data());
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = mut_intrinsic.vmwrite64(VMCS_GUEST_RIP, mut_rip + mut_len);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Clears the VPS's internal cache. Note that this is a
        ///     hardware specific function and doesn't change the actual
        ///     values stored in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        clear(tls_t &mut_tls, intrinsic_t const &intrinsic) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

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

            if (bsl::unlikely(mut_tls.ppid != m_assigned_ppid)) {
                bsl::error() << "vp "                                  // --
                             << bsl::hex(m_id)                         // --
                             << " is assigned to pp "                  // --
                             << bsl::hex(m_assigned_ppid)              // --
                             << " and cannot be operated on by pp "    // --
                             << bsl::hex(mut_tls.ppid)                 // --
                             << bsl::endl                              // --
                             << bsl::here();                           // --

                return bsl::errc_precondition;
            }

            mut_ret = this->ensure_this_vps_is_loaded(mut_tls, intrinsic);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmclear(&m_vmcs_phys);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_ret = intrinsic.vmload(&m_vmcs_phys);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            mut_tls.loaded_vpsid = m_id.get();
            m_vmcs_missing_registers.launched = {};

            return mut_ret;
        }

        /// <!-- description -->
        ///   @brief Dumps the vm_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_tls the current TLS block
        ///   @param intrinsic the intrinsics to use
        ///
        constexpr void
        dump(tls_t &mut_tls, intrinsic_t const &intrinsic) const noexcept
        {
            bsl::discard(mut_tls);

            if constexpr (BSL_DEBUG_LEVEL == bsl::CRITICAL_ONLY) {
                return;
            }

            auto const ret{this->ensure_this_vps_is_loaded(mut_tls, intrinsic)};
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
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

            if (mut_tls.active_vpsid == m_id) {
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

            this->dump_field("virtual_processor_identifier ", intrinsic.vmread16_quiet(VMCS_VIRTUAL_PROCESSOR_IDENTIFIER));
            this->dump_field("posted_interrupt_notification_vector ", intrinsic.vmread16_quiet(VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR));
            this->dump_field("eptp_index ", intrinsic.vmread16_quiet(VMCS_EPTP_INDEX));

            /// 16 Bit Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("es_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_ES_SELECTOR));
            this->dump_field("cs_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_CS_SELECTOR));
            this->dump_field("ss_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_SS_SELECTOR));
            this->dump_field("ds_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_DS_SELECTOR));
            this->dump_field("fs_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_FS_SELECTOR));
            this->dump_field("gs_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_GS_SELECTOR));
            this->dump_field("ldtr_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_LDTR_SELECTOR));
            this->dump_field("tr_selector ", intrinsic.vmread16_quiet(VMCS_GUEST_TR_SELECTOR));
            this->dump_field("interrupt_status ", intrinsic.vmread16_quiet(VMCS_GUEST_INTERRUPT_STATUS));
            this->dump_field("pml_index ", intrinsic.vmread16_quiet(VMCS_PML_INDEX));

            /// 64 Bit Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("address_of_io_bitmap_a ", intrinsic.vmread64_quiet(VMCS_ADDRESS_OF_IO_BITMAP_A));
            this->dump_field("address_of_io_bitmap_b ", intrinsic.vmread64_quiet(VMCS_ADDRESS_OF_IO_BITMAP_B));
            this->dump_field("address_of_msr_bitmaps ", intrinsic.vmread64_quiet(VMCS_ADDRESS_OF_MSR_BITMAPS));
            this->dump_field("vmexit_msr_store_address ", intrinsic.vmread64_quiet(VMCS_VMEXIT_MSR_STORE_ADDRESS));
            this->dump_field("vmexit_msr_load_address ", intrinsic.vmread64_quiet(VMCS_VMEXIT_MSR_LOAD_ADDRESS));
            this->dump_field("vmentry_msr_load_address ", intrinsic.vmread64_quiet(VMCS_VMENTRY_MSR_LOAD_ADDRESS));
            this->dump_field("executive_vmcs_pointer ", intrinsic.vmread64_quiet(VMCS_EXECUTIVE_VMCS_POINTER));
            this->dump_field("pml_address ", intrinsic.vmread64_quiet(VMCS_PML_ADDRESS));
            this->dump_field("tsc_offset ", intrinsic.vmread64_quiet(VMCS_TSC_OFFSET));
            this->dump_field("virtual_apic_address ", intrinsic.vmread64_quiet(VMCS_VIRTUAL_APIC_ADDRESS));
            this->dump_field("apic_access_address ", intrinsic.vmread64_quiet(VMCS_APIC_ACCESS_ADDRESS));
            this->dump_field("posted_interrupt_descriptor_address ", intrinsic.vmread64_quiet(VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS));
            this->dump_field("vm_function_controls ", intrinsic.vmread64_quiet(VMCS_VM_FUNCTION_CONTROLS));
            this->dump_field("ept_pointer ", intrinsic.vmread64_quiet(VMCS_EPT_POINTER));
            this->dump_field("eoi_exit_bitmap0 ", intrinsic.vmread64_quiet(VMCS_EOI_EXIT_BITMAP0));
            this->dump_field("eoi_exit_bitmap1 ", intrinsic.vmread64_quiet(VMCS_EOI_EXIT_BITMAP1));
            this->dump_field("eoi_exit_bitmap2 ", intrinsic.vmread64_quiet(VMCS_EOI_EXIT_BITMAP2));
            this->dump_field("eoi_exit_bitmap3 ", intrinsic.vmread64_quiet(VMCS_EOI_EXIT_BITMAP3));
            this->dump_field("eptp_list_address ", intrinsic.vmread64_quiet(VMCS_EPTP_LIST_ADDRESS));
            this->dump_field("vmread_bitmap_address ", intrinsic.vmread64_quiet(VMCS_VMREAD_BITMAP_ADDRESS));
            this->dump_field("vmwrite_bitmap_address ", intrinsic.vmread64_quiet(VMCS_VMWRITE_BITMAP_ADDRESS));
            this->dump_field("virt_exception_information_address ", intrinsic.vmread64_quiet(VMCS_VIRT_EXCEPTION_INFORMATION_ADDRESS));
            this->dump_field("xss_exiting_bitmap ", intrinsic.vmread64_quiet(VMCS_XSS_EXITING_BITMAP));
            this->dump_field("encls_exiting_bitmap ", intrinsic.vmread64_quiet(VMCS_ENCLS_EXITING_BITMAP));
            this->dump_field("sub_page_permission_table_pointer ", intrinsic.vmread64_quiet(VMCS_SUB_PAGE_PERMISSION_TABLE_POINTER));
            this->dump_field("tls_multiplier ", intrinsic.vmread64_quiet(VMCS_TLS_MULTIPLIER));

            /// 64 Bit Read-Only Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("guest_physical_address ", intrinsic.vmread64_quiet(VMCS_GUEST_PHYSICAL_ADDRESS));

            /// 64 Bit Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("vmcs_link_pointer ", intrinsic.vmread64_quiet(VMCS_VMCS_LINK_POINTER));
            this->dump_field("ia32_debugctl ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_DEBUGCTL));
            this->dump_field("ia32_pat ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_PAT));
            this->dump_field("ia32_efer ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_EFER));
            this->dump_field("ia32_perf_global_ctrl ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL));
            this->dump_field("guest_pdpte0 ", intrinsic.vmread64_quiet(VMCS_GUEST_PDPTE0));
            this->dump_field("guest_pdpte1 ", intrinsic.vmread64_quiet(VMCS_GUEST_PDPTE1));
            this->dump_field("guest_pdpte2 ", intrinsic.vmread64_quiet(VMCS_GUEST_PDPTE2));
            this->dump_field("guest_pdpte3 ", intrinsic.vmread64_quiet(VMCS_GUEST_PDPTE3));
            this->dump_field("ia32_bndcfgs ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_BNDCFGS));
            this->dump_field("guest_rtit_ctl ", intrinsic.vmread64_quiet(VMCS_GUEST_RTIT_CTL));
            this->dump_field("ia32_star ", bsl::make_safe(m_vmcs_missing_registers.guest_ia32_star));
            this->dump_field("ia32_lstar ", bsl::make_safe(m_vmcs_missing_registers.guest_ia32_lstar));
            this->dump_field("ia32_cstar ", bsl::make_safe(m_vmcs_missing_registers.guest_ia32_cstar));
            this->dump_field("ia32_fmask ", bsl::make_safe(m_vmcs_missing_registers.guest_ia32_fmask));
            this->dump_field("ia32_kernel_gs_base ", bsl::make_safe(m_vmcs_missing_registers.guest_ia32_kernel_gs_base));

            /// 32 Bit Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("pin_based_vm_execution_ctls ", intrinsic.vmread32_quiet(VMCS_PIN_BASED_VM_EXECUTION_CTLS));
            this->dump_field("primary_proc_based_vm_execution_ctls ", intrinsic.vmread32_quiet(VMCS_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS));
            this->dump_field("exception_bitmap ", intrinsic.vmread32_quiet(VMCS_EXCEPTION_BITMAP));
            this->dump_field("page_fault_error_code_mask ", intrinsic.vmread32_quiet(VMCS_PAGE_FAULT_ERROR_CODE_MASK));
            this->dump_field("page_fault_error_code_match ", intrinsic.vmread32_quiet(VMCS_PAGE_FAULT_ERROR_CODE_MATCH));
            this->dump_field("cr3_target_count ", intrinsic.vmread32_quiet(VMCS_CR3_TARGET_COUNT));
            this->dump_field("vmexit_ctls ", intrinsic.vmread32_quiet(VMCS_VMEXIT_CTLS));
            this->dump_field("vmexit_msr_store_count ", intrinsic.vmread32_quiet(VMCS_VMEXIT_MSR_STORE_COUNT));
            this->dump_field("vmexit_msr_load_count ", intrinsic.vmread32_quiet(VMCS_VMEXIT_MSR_LOAD_COUNT));
            this->dump_field("vmentry_ctls ", intrinsic.vmread32_quiet(VMCS_VMENTRY_CTLS));
            this->dump_field("vmentry_msr_load_count ", intrinsic.vmread32_quiet(VMCS_VMENTRY_MSR_LOAD_COUNT));
            this->dump_field("vmentry_interrupt_information_field ", intrinsic.vmread32_quiet(VMCS_VMENTRY_INTERRUPT_INFORMATION_FIELD));
            this->dump_field("vmentry_exception_error_code ", intrinsic.vmread32_quiet(VMCS_VMENTRY_EXCEPTION_ERROR_CODE));
            this->dump_field("vmentry_instruction_length ", intrinsic.vmread32_quiet(VMCS_VMENTRY_INSTRUCTION_LENGTH));
            this->dump_field("tpr_threshold ", intrinsic.vmread32_quiet(VMCS_TPR_THRESHOLD));
            this->dump_field("secondary_proc_based_vm_execution_ctls ", intrinsic.vmread32_quiet(VMCS_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS));
            this->dump_field("ple_gap ", intrinsic.vmread32_quiet(VMCS_PLE_GAP));
            this->dump_field("ple_window ", intrinsic.vmread32_quiet(VMCS_PLE_WINDOW));

            /// 32 Bit Read-Only Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("exit_reason ", intrinsic.vmread32_quiet(VMCS_EXIT_REASON));
            this->dump_field("vmexit_interruption_information ", intrinsic.vmread32_quiet(VMCS_VMEXIT_INTERRUPTION_INFORMATION));
            this->dump_field("vmexit_interruption_error_code ", intrinsic.vmread32_quiet(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE));
            this->dump_field("idt_vectoring_information_field ", intrinsic.vmread32_quiet(VMCS_IDT_VECTORING_INFORMATION_FIELD));
            this->dump_field("idt_vectoring_error_code ", intrinsic.vmread32_quiet(VMCS_IDT_VECTORING_ERROR_CODE));
            this->dump_field("vmexit_instruction_length ", intrinsic.vmread32_quiet(VMCS_VMEXIT_INSTRUCTION_LENGTH));
            this->dump_field("vmexit_instruction_information ", intrinsic.vmread32_quiet(VMCS_VMEXIT_INSTRUCTION_INFORMATION));

            /// 32 Bit Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("es_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_ES_LIMIT));
            this->dump_field("cs_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_CS_LIMIT));
            this->dump_field("ss_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_SS_LIMIT));
            this->dump_field("ds_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_DS_LIMIT));
            this->dump_field("fs_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_FS_LIMIT));
            this->dump_field("gs_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_GS_LIMIT));
            this->dump_field("ldtr_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_LDTR_LIMIT));
            this->dump_field("tr_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_TR_LIMIT));
            this->dump_field("gdtr_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_GDTR_LIMIT));
            this->dump_field("idtr_limit ", intrinsic.vmread32_quiet(VMCS_GUEST_IDTR_LIMIT));
            this->dump_field("es_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_ES_ACCESS_RIGHTS));
            this->dump_field("cs_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_CS_ACCESS_RIGHTS));
            this->dump_field("ss_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_SS_ACCESS_RIGHTS));
            this->dump_field("ds_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_DS_ACCESS_RIGHTS));
            this->dump_field("fs_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_FS_ACCESS_RIGHTS));
            this->dump_field("gs_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_GS_ACCESS_RIGHTS));
            this->dump_field("ldtr_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_LDTR_ACCESS_RIGHTS));
            this->dump_field("tr_access_rights ", intrinsic.vmread32_quiet(VMCS_GUEST_TR_ACCESS_RIGHTS));
            this->dump_field("guest_interruptibility_state ", intrinsic.vmread32_quiet(VMCS_GUEST_INTERRUPTIBILITY_STATE));
            this->dump_field("guest_activity_state ", intrinsic.vmread32_quiet(VMCS_GUEST_ACTIVITY_STATE));
            this->dump_field("guest_smbase ", intrinsic.vmread32_quiet(VMCS_GUEST_SMBASE));
            this->dump_field("ia32_sysenter_cs ", intrinsic.vmread32_quiet(VMCS_GUEST_IA32_SYSENTER_CS));
            this->dump_field("vmx_preemption_timer_value ", intrinsic.vmread32_quiet(VMCS_VMX_PREEMPTION_TIMER_VALUE));

            /// Natural-Width Control Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("cr0_guest_host_mask ", intrinsic.vmread64_quiet(VMCS_CR0_GUEST_HOST_MASK));
            this->dump_field("cr4_guest_host_mask ", intrinsic.vmread64_quiet(VMCS_CR4_GUEST_HOST_MASK));
            this->dump_field("cr0_read_shadow ", intrinsic.vmread64_quiet(VMCS_CR0_READ_SHADOW));
            this->dump_field("cr4_read_shadow ", intrinsic.vmread64_quiet(VMCS_CR4_READ_SHADOW));
            this->dump_field("cr3_target_value0 ", intrinsic.vmread64_quiet(VMCS_CR3_TARGET_VALUE0));
            this->dump_field("cr3_target_value1 ", intrinsic.vmread64_quiet(VMCS_CR3_TARGET_VALUE1));
            this->dump_field("cr3_target_value2 ", intrinsic.vmread64_quiet(VMCS_CR3_TARGET_VALUE2));
            this->dump_field("cr3_target_value3 ", intrinsic.vmread64_quiet(VMCS_CR3_TARGET_VALUE3));

            /// Natural-Width Read-Only Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("exit_qualification ", intrinsic.vmread64_quiet(VMCS_EXIT_QUALIFICATION));
            this->dump_field("io_rcx ", intrinsic.vmread64_quiet(VMCS_IO_RCX));
            this->dump_field("io_rsi ", intrinsic.vmread64_quiet(VMCS_IO_RSI));
            this->dump_field("io_rdi ", intrinsic.vmread64_quiet(VMCS_IO_RDI));
            this->dump_field("io_rip ", intrinsic.vmread64_quiet(VMCS_IO_RIP));
            this->dump_field("guest_linear_address ", intrinsic.vmread64_quiet(VMCS_GUEST_LINEAR_ADDRESS));

            /// Natural-Width Guest Fields
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            this->dump_field("cr0 ", intrinsic.vmread64_quiet(VMCS_GUEST_CR0));
            this->dump_field("cr2 ", bsl::make_safe(m_vmcs_missing_registers.guest_cr2));
            this->dump_field("cr3 ", intrinsic.vmread64_quiet(VMCS_GUEST_CR3));
            this->dump_field("cr4 ", intrinsic.vmread64_quiet(VMCS_GUEST_CR4));
            this->dump_field("es_base ", intrinsic.vmread64_quiet(VMCS_GUEST_ES_BASE));
            this->dump_field("cs_base ", intrinsic.vmread64_quiet(VMCS_GUEST_CS_BASE));
            this->dump_field("ss_base ", intrinsic.vmread64_quiet(VMCS_GUEST_SS_BASE));
            this->dump_field("ds_base ", intrinsic.vmread64_quiet(VMCS_GUEST_DS_BASE));
            this->dump_field("fs_base ", intrinsic.vmread64_quiet(VMCS_GUEST_FS_BASE));
            this->dump_field("gs_base ", intrinsic.vmread64_quiet(VMCS_GUEST_GS_BASE));
            this->dump_field("ldtr_base ", intrinsic.vmread64_quiet(VMCS_GUEST_LDTR_BASE));
            this->dump_field("tr_base ", intrinsic.vmread64_quiet(VMCS_GUEST_TR_BASE));
            this->dump_field("gdtr_base ", intrinsic.vmread64_quiet(VMCS_GUEST_GDTR_BASE));
            this->dump_field("idtr_base ", intrinsic.vmread64_quiet(VMCS_GUEST_IDTR_BASE));
            this->dump_field("dr6 ", bsl::make_safe(m_vmcs_missing_registers.guest_dr6));
            this->dump_field("dr7 ", intrinsic.vmread64_quiet(VMCS_GUEST_DR7));
            this->dump_field("rsp ", intrinsic.vmread64_quiet(VMCS_GUEST_RSP));
            this->dump_field("rip ", intrinsic.vmread64_quiet(VMCS_GUEST_RIP));
            this->dump_field("rflags ", intrinsic.vmread64_quiet(VMCS_GUEST_RFLAGS));
            this->dump_field("guest_pending_debug_exceptions ", intrinsic.vmread64_quiet(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS));
            this->dump_field("ia32_sysenter_esp ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_SYSENTER_ESP));
            this->dump_field("ia32_sysenter_eip ", intrinsic.vmread64_quiet(VMCS_GUEST_IA32_SYSENTER_EIP));

            /// Footer
            ///

            bsl::print() << bsl::ylw << "+--------------------------------------------------------------+";
            bsl::print() << bsl::rst << bsl::endl;

            // clang-format on
        }
    };
}

#endif
