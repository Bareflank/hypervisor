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

#include <mk_interface.hpp>
#include <vmcs_missing_registers_t.hpp>
#include <vmcs_t.hpp>

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
    extern "C" void dispatch_syscall_entry(void) noexcept;
    /// @brief entry point prototype
    extern "C" void intrinsic_vmexit(void) noexcept;

    /// @brief defines the value of an invalid VPSID
    constexpr bsl::safe_uint16 INVALID_VPSID{bsl::to_u16(0xFFFFU)};

    namespace details
    {
        /// @brief defines the VMX BASIC MSR
        constexpr bsl::safe_uint32 IA32_VMX_BASIC{bsl::to_u32(0x480)};
    }

    /// @class mk::vps_t
    ///
    /// <!-- description -->
    ///   @brief TODO
    ///
    /// <!-- template parameters -->
    ///   @tparam INTRINSIC_CONCEPT defines the type of intrinsics to use
    ///   @tparam PAGE_POOL_CONCEPT defines the type of page pool to use
    ///
    template<typename INTRINSIC_CONCEPT, typename PAGE_POOL_CONCEPT>
    class vps_t final
    {
        /// @brief stores true if initialized() has been executed
        bool m_initialized{};
        /// @brief stores a reference to the intrinsics to use
        INTRINSIC_CONCEPT *m_intrinsic{};
        /// @brief stores a reference to the page pool to use
        PAGE_POOL_CONCEPT *m_page_pool{};
        /// @brief stores the ID associated with this vps_t
        bsl::safe_uint16 m_id{bsl::safe_uint16::zero(true)};
        /// @brief stores the next vps_t in the vp_pool_t linked list
        vps_t *m_next{};

        /// @brief stores true if initialized() has been executed
        bool m_allocated{};
        /// @brief stores a pointer to the guest vmcs being managed by this VPS
        vmcs_t *m_vmcs{};
        /// @brief stores the physical address of the guest vmcs
        bsl::safe_uintmax m_vmcs_phys{bsl::safe_uintmax::zero(true)};
        /// @brief stores the rest of the state the vmcs doesn't
        vmcs_missing_registers_t m_vmcs_missing_registers{};

        /// <!-- description -->
        ///   @brief Stores the provided ES segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        set_es_segment_descriptor(STATE_SAVE_CONCEPT const *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::ZERO_U16 == state->es_selector) {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_ES_SELECTOR, bsl::ZERO_U16);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_ES_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_ES_LIMIT, bsl::ZERO_U32);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_ES_BASE, bsl::ZERO_U64);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }
            else {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_ES_SELECTOR, state->es_selector);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(
                    VMCS_GUEST_ES_ACCESS_RIGHTS, bsl::to_u32(state->es_attrib));
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_ES_LIMIT, state->es_limit);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_ES_BASE, state->es_base);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided CS segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        set_cs_segment_descriptor(STATE_SAVE_CONCEPT const *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::ZERO_U16 == state->cs_selector) {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_CS_SELECTOR, bsl::ZERO_U16);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_CS_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_CS_LIMIT, bsl::ZERO_U32);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_CS_BASE, bsl::ZERO_U64);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }
            else {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_CS_SELECTOR, state->cs_selector);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(
                    VMCS_GUEST_CS_ACCESS_RIGHTS, bsl::to_u32(state->cs_attrib));
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_CS_LIMIT, state->cs_limit);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_CS_BASE, state->cs_base);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided SS segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        set_ss_segment_descriptor(STATE_SAVE_CONCEPT const *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::ZERO_U16 == state->ss_selector) {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_SS_SELECTOR, bsl::ZERO_U16);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_SS_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_SS_LIMIT, bsl::ZERO_U32);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_SS_BASE, bsl::ZERO_U64);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }
            else {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_SS_SELECTOR, state->ss_selector);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(
                    VMCS_GUEST_SS_ACCESS_RIGHTS, bsl::to_u32(state->ss_attrib));
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_SS_LIMIT, state->ss_limit);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_SS_BASE, state->ss_base);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided DS segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        set_ds_segment_descriptor(STATE_SAVE_CONCEPT const *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::ZERO_U16 == state->ds_selector) {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_DS_SELECTOR, bsl::ZERO_U16);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_DS_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_DS_LIMIT, bsl::ZERO_U32);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_DS_BASE, bsl::ZERO_U64);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }
            else {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_DS_SELECTOR, state->ds_selector);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(
                    VMCS_GUEST_DS_ACCESS_RIGHTS, bsl::to_u32(state->ds_attrib));
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_DS_LIMIT, state->ds_limit);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_DS_BASE, state->ds_base);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided FS segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        set_fs_segment_descriptor(STATE_SAVE_CONCEPT const *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::ZERO_U16 == state->fs_selector) {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_FS_SELECTOR, bsl::ZERO_U16);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_FS_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_FS_LIMIT, bsl::ZERO_U32);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_FS_BASE, bsl::ZERO_U64);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }
            else {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_FS_SELECTOR, state->fs_selector);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(
                    VMCS_GUEST_FS_ACCESS_RIGHTS, bsl::to_u32(state->fs_attrib));
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_FS_LIMIT, state->fs_limit);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_FS_BASE, state->fs_base);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided GS segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        set_gs_segment_descriptor(STATE_SAVE_CONCEPT const *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::ZERO_U16 == state->gs_selector) {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_GS_SELECTOR, bsl::ZERO_U16);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_GS_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_GS_LIMIT, bsl::ZERO_U32);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_GS_BASE, bsl::ZERO_U64);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }
            else {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_GS_SELECTOR, state->gs_selector);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(
                    VMCS_GUEST_GS_ACCESS_RIGHTS, bsl::to_u32(state->gs_attrib));
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_GS_LIMIT, state->gs_limit);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_GS_BASE, state->gs_base);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided LDTR segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        set_ldtr_segment_descriptor(STATE_SAVE_CONCEPT const *const state) &noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::ZERO_U16 == state->ldtr_selector) {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_LDTR_SELECTOR, bsl::ZERO_U16);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_LDTR_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_LDTR_LIMIT, bsl::ZERO_U32);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_LDTR_BASE, bsl::ZERO_U64);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }
            else {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_LDTR_SELECTOR, state->ldtr_selector);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(
                    VMCS_GUEST_LDTR_ACCESS_RIGHTS, bsl::to_u32(state->ldtr_attrib));
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_LDTR_LIMIT, state->ldtr_limit);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_LDTR_BASE, state->ldtr_base);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the provided TR segment state info in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        set_tr_segment_descriptor(STATE_SAVE_CONCEPT const *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::ZERO_U16 == state->tr_selector) {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_TR_SELECTOR, bsl::ZERO_U16);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_TR_ACCESS_RIGHTS, VMCS_UNUSABLE_SEGMENT);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_TR_LIMIT, bsl::ZERO_U32);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_TR_BASE, bsl::ZERO_U64);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }
            else {
                ret = m_intrinsic->vmwrite16(VMCS_GUEST_TR_SELECTOR, state->tr_selector);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(
                    VMCS_GUEST_TR_ACCESS_RIGHTS, bsl::to_u32(state->tr_attrib));
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite32(VMCS_GUEST_TR_LIMIT, state->tr_limit);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }

                ret = m_intrinsic->vmwrite64(VMCS_GUEST_TR_BASE, state->tr_base);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return bsl::errc_failure;
                }
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the ES segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        get_es_segment_descriptor(STATE_SAVE_CONCEPT *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = m_intrinsic->vmread16(VMCS_GUEST_ES_SELECTOR, selector.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_ES_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_ES_LIMIT, limit.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_ES_BASE, base.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state->es_selector = bsl::ZERO_U16.get();
                state->es_attrib = bsl::ZERO_U16.get();
                state->es_limit = bsl::ZERO_U32.get();
                state->es_base = bsl::ZERO_U64.get();
            }
            else {
                state->es_selector = selector.get();
                state->es_attrib = bsl::to_u16(access_rights).get();
                state->es_limit = limit.get();
                state->es_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the CS segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        get_cs_segment_descriptor(STATE_SAVE_CONCEPT *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = m_intrinsic->vmread16(VMCS_GUEST_CS_SELECTOR, selector.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_CS_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_CS_LIMIT, limit.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_CS_BASE, base.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state->cs_selector = bsl::ZERO_U16.get();
                state->cs_attrib = bsl::ZERO_U16.get();
                state->cs_limit = bsl::ZERO_U32.get();
                state->cs_base = bsl::ZERO_U64.get();
            }
            else {
                state->cs_selector = selector.get();
                state->cs_attrib = bsl::to_u16(access_rights).get();
                state->cs_limit = limit.get();
                state->cs_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the SS segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        get_ss_segment_descriptor(STATE_SAVE_CONCEPT *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = m_intrinsic->vmread16(VMCS_GUEST_SS_SELECTOR, selector.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_SS_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_SS_LIMIT, limit.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_SS_BASE, base.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state->ss_selector = bsl::ZERO_U16.get();
                state->ss_attrib = bsl::ZERO_U16.get();
                state->ss_limit = bsl::ZERO_U32.get();
                state->ss_base = bsl::ZERO_U64.get();
            }
            else {
                state->ss_selector = selector.get();
                state->ss_attrib = bsl::to_u16(access_rights).get();
                state->ss_limit = limit.get();
                state->ss_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the DS segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        get_ds_segment_descriptor(STATE_SAVE_CONCEPT *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = m_intrinsic->vmread16(VMCS_GUEST_DS_SELECTOR, selector.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_DS_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_DS_LIMIT, limit.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_DS_BASE, base.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state->ds_selector = bsl::ZERO_U16.get();
                state->ds_attrib = bsl::ZERO_U16.get();
                state->ds_limit = bsl::ZERO_U32.get();
                state->ds_base = bsl::ZERO_U64.get();
            }
            else {
                state->ds_selector = selector.get();
                state->ds_attrib = bsl::to_u16(access_rights).get();
                state->ds_limit = limit.get();
                state->ds_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the GS segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        get_gs_segment_descriptor(STATE_SAVE_CONCEPT *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = m_intrinsic->vmread16(VMCS_GUEST_GS_SELECTOR, selector.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_GS_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_GS_LIMIT, limit.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_GS_BASE, base.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state->gs_selector = bsl::ZERO_U16.get();
                state->gs_attrib = bsl::ZERO_U16.get();
                state->gs_limit = bsl::ZERO_U32.get();
                state->gs_base = bsl::ZERO_U64.get();
            }
            else {
                state->gs_selector = selector.get();
                state->gs_attrib = bsl::to_u16(access_rights).get();
                state->gs_limit = limit.get();
                state->gs_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the FS segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        get_fs_segment_descriptor(STATE_SAVE_CONCEPT *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = m_intrinsic->vmread16(VMCS_GUEST_FS_SELECTOR, selector.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_FS_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_FS_LIMIT, limit.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_FS_BASE, base.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state->fs_selector = bsl::ZERO_U16.get();
                state->fs_attrib = bsl::ZERO_U16.get();
                state->fs_limit = bsl::ZERO_U32.get();
                state->fs_base = bsl::ZERO_U64.get();
            }
            else {
                state->fs_selector = selector.get();
                state->fs_attrib = bsl::to_u16(access_rights).get();
                state->fs_limit = limit.get();
                state->fs_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the LDTR segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        get_ldtr_segment_descriptor(STATE_SAVE_CONCEPT *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = m_intrinsic->vmread16(VMCS_GUEST_LDTR_SELECTOR, selector.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_LDTR_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_LDTR_LIMIT, limit.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_LDTR_BASE, base.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state->ldtr_selector = bsl::ZERO_U16.get();
                state->ldtr_attrib = bsl::ZERO_U16.get();
                state->ldtr_limit = bsl::ZERO_U32.get();
                state->ldtr_base = bsl::ZERO_U64.get();
            }
            else {
                state->ldtr_selector = selector.get();
                state->ldtr_attrib = bsl::to_u16(access_rights).get();
                state->ldtr_limit = limit.get();
                state->ldtr_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the TR segment info in the VPS to the provided
        ///     state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param state the state to set
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        get_tr_segment_descriptor(STATE_SAVE_CONCEPT *const state) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint16 selector{};
            bsl::safe_uint32 access_rights{};
            bsl::safe_uint32 limit{};
            bsl::safe_uint64 base{};

            ret = m_intrinsic->vmread16(VMCS_GUEST_TR_SELECTOR, selector.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_TR_ACCESS_RIGHTS, access_rights.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread32(VMCS_GUEST_TR_LIMIT, limit.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_TR_BASE, base.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (VMCS_UNUSABLE_SEGMENT == access_rights) {
                state->tr_selector = bsl::ZERO_U16.get();
                state->tr_attrib = bsl::ZERO_U16.get();
                state->tr_limit = bsl::ZERO_U32.get();
                state->tr_base = bsl::ZERO_U64.get();
            }
            else {
                state->tr_selector = selector.get();
                state->tr_attrib = bsl::to_u16(access_rights).get();
                state->tr_limit = limit.get();
                state->tr_base = base.get();
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Ensures that this VPS is loaded
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        ensure_this_vps_is_loaded(TLS_CONCEPT &tls) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (this == tls.loaded_vps) {
                return bsl::errc_success;
            }

            ret = m_intrinsic->vmload(&m_vmcs_phys);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            tls.loaded_vps = this;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Ensures that this VPS is loaded
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        init_vmcs(TLS_CONCEPT &tls) noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            auto *const state{tls.mk_state};

            m_vmcs->revision_id =
                bsl::to_u32_unsafe(m_intrinsic->rdmsr(details::IA32_VMX_BASIC)).get();

            if (bsl::unlikely(!this->ensure_this_vps_is_loaded(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite16(VMCS_HOST_ES_SELECTOR, state->es_selector);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite16(VMCS_HOST_CS_SELECTOR, state->cs_selector);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite16(VMCS_HOST_SS_SELECTOR, state->ss_selector);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite16(VMCS_HOST_DS_SELECTOR, state->ds_selector);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite16(VMCS_HOST_FS_SELECTOR, state->fs_selector);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite16(VMCS_HOST_GS_SELECTOR, state->gs_selector);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite16(VMCS_HOST_TR_SELECTOR, state->tr_selector);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_IA32_PAT, state->ia32_pat);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_IA32_EFER, state->ia32_efer);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_IA32_PAT, state->ia32_pat);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_IA32_SYSENTER_CS, state->ia32_sysenter_cs);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_CR0, state->cr0);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_CR3, m_intrinsic->cr3());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_CR4, state->cr4);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_FS_BASE, tls.tp);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_GS_BASE, bsl::to_umax(&tls));
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_TR_BASE, state->tr_base);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_GDTR_BASE, bsl::to_umax(state->gdtr.base));
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_IDTR_BASE, bsl::to_umax(state->idtr.base));
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_IA32_SYSENTER_ESP, state->ia32_sysenter_esp);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_IA32_SYSENTER_EIP, state->ia32_sysenter_eip);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_HOST_RIP, bsl::to_umax(&intrinsic_vmexit));
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_vmcs_missing_registers.host_ia32_star = state->ia32_star;
            m_vmcs_missing_registers.host_ia32_lstar = bsl::to_umax(&dispatch_syscall_entry).get();
            m_vmcs_missing_registers.host_ia32_cstar = state->ia32_cstar;
            m_vmcs_missing_registers.host_ia32_fmask = state->ia32_fmask;
            m_vmcs_missing_registers.host_ia32_kernel_gs_base = state->ia32_kernel_gs_base;

            return bsl::errc_success;
        }

    public:
        /// @brief an alias for INTRINSIC_CONCEPT
        using intrinsic_type = INTRINSIC_CONCEPT;
        /// @brief an alias for PAGE_POOL_CONCEPT
        using page_pool_type = PAGE_POOL_CONCEPT;

        /// <!-- description -->
        ///   @brief Default constructor
        ///
        constexpr vps_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Initializes this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @param intrinsic the intrinsics to use
        ///   @param page_pool the page pool to use
        ///   @param i the ID for this vps_t
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] constexpr auto
        initialize(
            INTRINSIC_CONCEPT *const intrinsic,
            PAGE_POOL_CONCEPT *const page_pool,
            bsl::safe_uint16 const &i) &noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(m_initialized)) {
                bsl::error() << "vm_t already initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            m_intrinsic = intrinsic;
            if (bsl::unlikely(nullptr == m_intrinsic)) {
                bsl::error() << "invalid intrinsic\n" << bsl::here();
                return bsl::errc_failure;
            }

            m_page_pool = page_pool;
            if (bsl::unlikely(nullptr == m_page_pool)) {
                bsl::error() << "invalid page_pool\n" << bsl::here();
                return bsl::errc_failure;
            }

            m_id = i;
            if (bsl::unlikely(!i)) {
                bsl::error() << "invalid id\n" << bsl::here();
                return bsl::errc_failure;
            }

            release_on_error.ignore();
            m_initialized = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vps_t
        ///
        constexpr void
        release() &noexcept
        {
            this->deallocate();

            m_next = {};
            m_id = bsl::safe_uint16::zero(true);
            m_page_pool = {};
            m_intrinsic = {};
            m_initialized = {};
        }

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~vps_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr vps_t(vps_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr vps_t(vps_t &&o) noexcept = default;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(vps_t const &o) &noexcept -> vps_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(vps_t &&o) &noexcept -> vps_t & = default;

        /// <!-- description -->
        ///   @brief Returns the ID of this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of this vps_t
        ///
        [[nodiscard]] constexpr auto
        id() const &noexcept -> bsl::safe_uint16 const &
        {
            return m_id;
        }

        /// <!-- description -->
        ///   @brief Returns the next vps_t in the vps_pool_t linked list
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the next vps_t in the vps_pool_t linked list
        ///
        [[nodiscard]] constexpr auto
        next() const &noexcept -> vps_t *
        {
            return m_next;
        }

        /// <!-- description -->
        ///   @brief Sets the next vps_t in the vps_pool_t linked list
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the next vps_t in the vps_pool_t linked list to set
        ///
        constexpr void
        set_next(vps_t *val) &noexcept
        {
            m_next = val;
        }

        /// <!-- description -->
        ///   @brief Allocates this vps_t
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        allocate(TLS_CONCEPT &tls) &noexcept -> bsl::errc_type
        {
            if (bsl::unlikely(!m_initialized)) {
                bsl::error() << "vps_t not initialized\n" << bsl::here();
                return bsl::errc_failure;
            }

            bsl::finally release_on_error{[this]() noexcept -> void {
                this->release();
            }};

            m_vmcs = m_page_pool->template allocate<vmcs_t>();
            if (bsl::unlikely(nullptr == m_vmcs)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_vmcs_phys = m_page_pool->virt_to_phys(m_vmcs);
            if (bsl::unlikely(!m_vmcs_phys)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->init_vmcs(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            /// TODO:
            /// - Extensions should not be able to touch host state fields.
            ///

            release_on_error.ignore();
            m_allocated = true;

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Deallocates this vps_t
        ///
        constexpr void
        deallocate() &noexcept
        {
            m_vmcs_missing_registers = {};
            m_vmcs_phys = bsl::safe_uintmax::zero(true);

            if (nullptr != m_page_pool) {
                m_page_pool->deallocate(m_vmcs);
                m_vmcs = {};
            }
            else {
                bsl::touch();
            }

            m_allocated = {};
        }

        /// <!-- description -->
        ///   @brief Stores the provided state in the VPS.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param tls the current TLS block
        ///   @param state the state to set the VPS to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT, typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        state_save_to_vps(TLS_CONCEPT &tls, STATE_SAVE_CONCEPT const *const state) &noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::unlikely(!m_allocated)) {
                bsl::error() << "invalid vps\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(nullptr == state)) {
                bsl::error() << "invalid state\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->ensure_this_vps_is_loaded(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RAX, state->rax);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RBX, state->rbx);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RCX, state->rcx);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RDX, state->rdx);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RBP, state->rbp);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RSI, state->rsi);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RDI, state->rdi);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R8, state->r8);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R9, state->r9);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R10, state->r10);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R11, state->r11);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R12, state->r12);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R13, state->r13);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R14, state->r14);
            m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R15, state->r15);

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_RSP, state->rsp);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_RIP, state->rip);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_RFLAGS, state->rflags);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const gdtr_limit{bsl::to_u32(state->gdtr.limit)};
            ret = m_intrinsic->vmwrite32(VMCS_GUEST_GDTR_LIMIT, gdtr_limit);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const gdtr_base{bsl::to_umax(state->gdtr.base)};
            ret = m_intrinsic->vmwrite64(VMCS_GUEST_GDTR_BASE, gdtr_base);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const idtr_limit{bsl::to_u32(state->idtr.limit)};
            ret = m_intrinsic->vmwrite32(VMCS_GUEST_IDTR_LIMIT, idtr_limit);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            auto const idtr_base{bsl::to_umax(state->idtr.base)};
            ret = m_intrinsic->vmwrite64(VMCS_GUEST_IDTR_BASE, idtr_base);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->set_es_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->set_cs_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->set_ss_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->set_ds_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->set_fs_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->set_gs_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->set_ldtr_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->set_tr_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_CR0, state->cr0);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_vmcs_missing_registers.cr2 = state->cr2;

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_CR3, state->cr3);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_CR4, state->cr4);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_vmcs_missing_registers.dr6 = state->dr6;

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_DR7, state->dr7);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_IA32_EFER, state->ia32_efer);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_vmcs_missing_registers.guest_ia32_star = state->ia32_star;
            m_vmcs_missing_registers.guest_ia32_lstar = state->ia32_lstar;
            m_vmcs_missing_registers.guest_ia32_cstar = state->ia32_cstar;
            m_vmcs_missing_registers.guest_ia32_fmask = state->ia32_fmask;

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_FS_BASE, state->ia32_fs_base);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_GS_BASE, state->ia32_gs_base);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            m_vmcs_missing_registers.guest_ia32_kernel_gs_base = state->ia32_kernel_gs_base;

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_IA32_SYSENTER_CS, state->ia32_sysenter_cs);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_IA32_SYSENTER_ESP, state->ia32_sysenter_esp);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_IA32_SYSENTER_EIP, state->ia32_sysenter_eip);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_IA32_PAT, state->ia32_pat);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_IA32_DEBUGCTL, state->ia32_debugctl);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Stores the VPS state in the provided state save.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam STATE_SAVE_CONCEPT the type of state save to use
        ///   @param tls the current TLS block
        ///   @param state the state save to store the VPS state to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT, typename STATE_SAVE_CONCEPT>
        [[nodiscard]] constexpr auto
        vps_to_state_save(TLS_CONCEPT &tls, STATE_SAVE_CONCEPT *const state) &noexcept
            -> bsl::errc_type
        {
            bsl::errc_type ret{};

            if (bsl::unlikely(!m_allocated)) {
                bsl::error() << "invalid vps\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(nullptr == state)) {
                bsl::error() << "invalid state\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->ensure_this_vps_is_loaded(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            state->rax = m_intrinsic->tls_reg(syscall::TLS_OFFSET_RAX).get();
            state->rbx = m_intrinsic->tls_reg(syscall::TLS_OFFSET_RBX).get();
            state->rcx = m_intrinsic->tls_reg(syscall::TLS_OFFSET_RCX).get();
            state->rdx = m_intrinsic->tls_reg(syscall::TLS_OFFSET_RDX).get();
            state->rbp = m_intrinsic->tls_reg(syscall::TLS_OFFSET_RBP).get();
            state->rsi = m_intrinsic->tls_reg(syscall::TLS_OFFSET_RSI).get();
            state->rdi = m_intrinsic->tls_reg(syscall::TLS_OFFSET_RDI).get();
            state->r8 = m_intrinsic->tls_reg(syscall::TLS_OFFSET_R8).get();
            state->r9 = m_intrinsic->tls_reg(syscall::TLS_OFFSET_R9).get();
            state->r10 = m_intrinsic->tls_reg(syscall::TLS_OFFSET_R10).get();
            state->r11 = m_intrinsic->tls_reg(syscall::TLS_OFFSET_R11).get();
            state->r12 = m_intrinsic->tls_reg(syscall::TLS_OFFSET_R12).get();
            state->r13 = m_intrinsic->tls_reg(syscall::TLS_OFFSET_R13).get();
            state->r14 = m_intrinsic->tls_reg(syscall::TLS_OFFSET_R14).get();
            state->r15 = m_intrinsic->tls_reg(syscall::TLS_OFFSET_R15).get();

            ret = m_intrinsic->vmread64(VMCS_GUEST_RSP, &state->rsp);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_RIP, &state->rip);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_RFLAGS, &state->rflags);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread16(VMCS_GUEST_GDTR_LIMIT, &state->gdtr.limit);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            bsl::safe_uint64 gdtr_base{};
            ret = m_intrinsic->vmread64(VMCS_GUEST_GDTR_BASE, gdtr_base.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            state->gdtr.base = bsl::to_ptr<bsl::uint64 *>(gdtr_base);

            ret = m_intrinsic->vmread16(VMCS_GUEST_IDTR_LIMIT, &state->idtr.limit);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            bsl::safe_uint64 idtr_base{};
            ret = m_intrinsic->vmread64(VMCS_GUEST_IDTR_BASE, idtr_base.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            state->idtr.base = bsl::to_ptr<bsl::uint64 *>(idtr_base);

            if (bsl::unlikely(!this->get_es_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->get_cs_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->get_ss_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->get_ds_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->get_fs_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->get_gs_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->get_ldtr_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->get_tr_segment_descriptor(state))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_CR0, &state->cr0);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            state->cr2 = m_vmcs_missing_registers.cr2;

            ret = m_intrinsic->vmread64(VMCS_GUEST_CR3, &state->cr3);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_CR4, &state->cr4);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            state->dr6 = m_vmcs_missing_registers.dr6;

            ret = m_intrinsic->vmread64(VMCS_GUEST_DR7, &state->dr7);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_IA32_EFER, &state->ia32_efer);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            state->ia32_star = m_vmcs_missing_registers.guest_ia32_star;
            state->ia32_lstar = m_vmcs_missing_registers.guest_ia32_lstar;
            state->ia32_cstar = m_vmcs_missing_registers.guest_ia32_cstar;
            state->ia32_fmask = m_vmcs_missing_registers.guest_ia32_fmask;

            ret = m_intrinsic->vmread64(VMCS_GUEST_FS_BASE, &state->ia32_fs_base);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_GS_BASE, &state->ia32_gs_base);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            state->ia32_kernel_gs_base = m_vmcs_missing_registers.guest_ia32_kernel_gs_base;

            ret = m_intrinsic->vmread64(VMCS_GUEST_IA32_SYSENTER_CS, &state->ia32_sysenter_cs);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_IA32_SYSENTER_ESP, &state->ia32_sysenter_esp);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_IA32_SYSENTER_EIP, &state->ia32_sysenter_eip);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_IA32_PAT, &state->ia32_pat);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_IA32_DEBUGCTL, &state->ia32_debugctl);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Reads a field from the VPS given the index of
        ///     the field to read.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam FIELD_TYPE the type (i.e., size) of field to read
        ///   @param tls the current TLS block
        ///   @param index the index of the field to read from the VPS
        ///   @return Returns the value of the requested field from the
        ///     VPS or bsl::safe_integral<FIELD_TYPE>::zero(true)
        ///     on failure.
        ///
        template<typename FIELD_TYPE, typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        read(TLS_CONCEPT &tls, bsl::safe_uintmax const &index) &noexcept
            -> bsl::safe_integral<FIELD_TYPE>
        {
            /// TODO:
            /// - Implement a field type checker to make sure the user is
            ///   using the proper field type here. Make sure that this field
            ///   type checker is only turned on with debug builds.
            ///

            bsl::errc_type ret{};
            bsl::safe_integral<FIELD_TYPE> val{};

            if (bsl::unlikely(!m_allocated)) {
                bsl::error() << "invalid vps\n" << bsl::here();
                return bsl::safe_integral<FIELD_TYPE>::zero(true);
            }

            if (bsl::unlikely(!this->ensure_this_vps_is_loaded(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_integral<FIELD_TYPE>::zero(true);
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint16>::value) {
                ret = m_intrinsic->vmread16(index, val.data());
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return val;
                }

                return val;
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint32>::value) {
                ret = m_intrinsic->vmread32(index, val.data());
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return val;
                }

                return val;
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint64>::value) {
                ret = m_intrinsic->vmread64(index, val.data());
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return val;
                }

                return val;
            }

            bsl::error() << "unsupported field type\n" << bsl::here();
            return bsl::safe_integral<FIELD_TYPE>::zero(true);
        }

        /// <!-- description -->
        ///   @brief Writes a field to the VPS given the index of
        ///     the field and the value to write.
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @tparam FIELD_TYPE the type (i.e., size) of field to write
        ///   @param tls the current TLS block
        ///   @param index the index of the field to write to the VPS
        ///   @param value the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename FIELD_TYPE, typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        write(
            TLS_CONCEPT &tls,
            bsl::safe_uintmax const &index,
            bsl::safe_integral<FIELD_TYPE> const &value) &noexcept -> bsl::errc_type
        {
            /// TODO:
            /// - Implement a field type checker to make sure the user is
            ///   using the proper field type here. Make sure that this field
            ///   type checker is only turned on with debug builds.
            ///

            bsl::errc_type ret{};

            if (bsl::unlikely(!m_allocated)) {
                bsl::error() << "invalid vps\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!value)) {
                bsl::error() << "invalid val: "    // --
                             << bsl::hex(value)    // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->ensure_this_vps_is_loaded(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            constexpr auto vmcs_pinbased_ctls_idx{bsl::to_umax(0x4000U)};
            constexpr auto vmcs_exit_ctls_idx{bsl::to_umax(0x400CU)};
            constexpr auto vmcs_entry_ctls_idx{bsl::to_umax(0x4012U)};

            bsl::safe_integral<FIELD_TYPE> sanitized{value};

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint32>::value) {
                switch (index.get()) {
                    case vmcs_pinbased_ctls_idx.get(): {
                        constexpr auto vmcs_pinbased_ctls_mask{bsl::to_u32(0x28U)};
                        sanitized |= vmcs_pinbased_ctls_mask;
                        break;
                    }

                    case vmcs_exit_ctls_idx.get(): {
                        constexpr auto vmcs_exit_ctls_mask{bsl::to_u32(0x3C0204U)};
                        sanitized |= vmcs_exit_ctls_mask;
                        break;
                    }

                    case vmcs_entry_ctls_idx.get(): {
                        constexpr auto vmcs_entry_ctls_mask{bsl::to_u32(0xC204U)};
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
                        bsl::error()
                            << "invalid integer type for field: " << bsl::hex(index) << bsl::endl
                            << bsl::here();

                        return bsl::errc_failure;
                    }

                    case vmcs_exit_ctls_idx.get(): {
                        bsl::error()
                            << "invalid integer type for field: " << bsl::hex(index) << bsl::endl
                            << bsl::here();

                        return bsl::errc_failure;
                    }

                    case vmcs_entry_ctls_idx.get(): {
                        bsl::error()
                            << "invalid integer type for field: " << bsl::hex(index) << bsl::endl
                            << bsl::here();

                        return bsl::errc_failure;
                    }

                    default: {
                        break;
                    }
                }
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint16>::value) {
                ret = m_intrinsic->vmwrite16(index, sanitized);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint32>::value) {
                ret = m_intrinsic->vmwrite32(index, sanitized);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return ret;
                }

                return ret;
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint64>::value) {
                ret = m_intrinsic->vmwrite64(index, sanitized);
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
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @param reg a bf_reg_t defining the field to read from the VPS
        ///   @return Returns the value of the requested field from the
        ///     VPS or bsl::safe_uintmax::zero(true) on failure.
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        read_reg(TLS_CONCEPT &tls, syscall::bf_reg_t const reg) &noexcept -> bsl::safe_uintmax
        {
            bsl::safe_uint64 index{};

            if (bsl::unlikely(!m_allocated)) {
                bsl::error() << "invalid vps\n" << bsl::here();
                return bsl::safe_uintmax::zero(true);
            }

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_rax: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_RAX);
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_RBX);
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_RCX);
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_RDX);
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_RBP);
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_RSI);
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_RDI);
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_R8);
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_R9);
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_R10);
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_R11);
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_R12);
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_R13);
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_R14);
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    return m_intrinsic->tls_reg(syscall::TLS_OFFSET_R15);
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
                    return bsl::safe_uintmax::zero(true);
                }
            }

            auto val{this->read<bsl::uint64>(tls, index)};
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
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @param reg a bf_reg_t defining the field to write to the VPS
        ///   @param val the value to write to the VPS
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        write_reg(
            TLS_CONCEPT &tls, syscall::bf_reg_t const reg, bsl::safe_uintmax const &val) &noexcept
            -> bsl::errc_type
        {
            bsl::safe_uint64 index{};

            if (bsl::unlikely(!m_allocated)) {
                bsl::error() << "invalid vps\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val: "    // --
                             << bsl::hex(val)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            switch (reg) {
                case syscall::bf_reg_t::bf_reg_t_rax: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RAX, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbx: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RBX, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rcx: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RCX, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdx: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RDX, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rbp: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RBP, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rsi: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RSI, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_rdi: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_RDI, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r8: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R8, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r9: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R9, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r10: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R10, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r11: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R11, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r12: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R12, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r13: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R13, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r14: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R14, val);
                    return bsl::errc_success;
                }

                case syscall::bf_reg_t::bf_reg_t_r15: {
                    m_intrinsic->set_tls_reg(syscall::TLS_OFFSET_R15, val);
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
                    return bsl::errc_failure;
                }
            }

            auto const ret{this->write<bsl::uint64>(tls, index, val)};
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
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @return Returns the VMExit reason on success, or
        ///     bsl::safe_uintmax::zero(true) on failure.
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        run(TLS_CONCEPT &tls) &noexcept -> bsl::safe_uintmax
        {
            constexpr bsl::safe_uintmax invalid_exit_reason{bsl::to_umax(0xFFFFFFFFFFFFFFFFU)};

            if (bsl::unlikely(!m_allocated)) {
                bsl::error() << "invalid vps\n" << bsl::here();
                return bsl::safe_uintmax::zero(true);
            }

            if (bsl::unlikely(!this->ensure_this_vps_is_loaded(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::safe_uintmax::zero(true);
            }

            auto const exit_reason{details::intrinsic_vmrun(&m_vmcs_missing_registers)};
            if (invalid_exit_reason == exit_reason) {
                this->dump(tls);

                bsl::error() << "vmlaunch/vmresume failed\n" << bsl::here();
                return bsl::safe_uintmax::zero(true);
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
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        template<typename TLS_CONCEPT>
        [[nodiscard]] constexpr auto
        advance_ip(TLS_CONCEPT &tls) &noexcept -> bsl::errc_type
        {
            bsl::errc_type ret{};
            bsl::safe_uint64 rip{};
            bsl::safe_uint64 len{};

            if (bsl::unlikely(!m_allocated)) {
                bsl::error() << "invalid vps\n" << bsl::here();
                return bsl::errc_failure;
            }

            if (bsl::unlikely(!this->ensure_this_vps_is_loaded(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_GUEST_RIP, rip.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmread64(VMCS_VMEXIT_INSTRUCTION_LENGTH, len.data());
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            ret = m_intrinsic->vmwrite64(VMCS_GUEST_RIP, rip + len);
            if (bsl::unlikely(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return ret;
        }

        /// <!-- description -->
        ///   @brief Dumps the contents of a VMCS field to the console
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam FIELD_TYPE the type (i.e., size) of field to read
        ///   @param name the name of the field
        ///   @param type the field's type
        ///   @param index the index of the field
        ///
        template<typename FIELD_TYPE>
        constexpr void
        dump_vmcs_field(
            bsl::string_view const &name,
            bsl::string_view const &type,
            bsl::safe_uintmax const &index) noexcept
        {
            constexpr bsl::safe_uintmax field_width{bsl::to_umax(44)};

            bsl::errc_type ret{};
            bsl::safe_integral<FIELD_TYPE> val{};

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint16>::value) {
                ret = m_intrinsic->vmread16_quiet(index, val.data());
                if (bsl::unlikely(!ret)) {
                    val = bsl::safe_integral<FIELD_TYPE>::zero(true);
                }
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint32>::value) {
                ret = m_intrinsic->vmread32_quiet(index, val.data());
                if (bsl::unlikely(!ret)) {
                    val = bsl::safe_integral<FIELD_TYPE>::zero(true);
                }
            }

            if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint64>::value) {
                ret = m_intrinsic->vmread64_quiet(index, val.data());
                if (bsl::unlikely(!ret)) {
                    val = bsl::safe_integral<FIELD_TYPE>::zero(true);
                }
            }

            bsl::print<bsl::V>() << bsl::yellow << "| " << bsl::reset_color;
            bsl::print<bsl::V>() << name;

            for (bsl::safe_uintmax i{}; i < field_width - name.length(); ++i) {
                bsl::print<bsl::V>() << ' ';
            }

            bsl::print<bsl::V>() << bsl::yellow << " | " << bsl::reset_color;
            bsl::print<bsl::V>() << type;
            bsl::print<bsl::V>() << bsl::yellow << " | " << bsl::reset_color;

            if (val) {
                if (val.is_zero()) {
                    bsl::print<bsl::V>() << bsl::black << bsl::hex(val) << bsl::reset_color;
                }
                else {
                    bsl::print<bsl::V>() << bsl::hex(val);
                }

                if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint16>::value) {
                    bsl::print<bsl::V>() << bsl::yellow << "             |\n" << bsl::reset_color;
                }

                if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint32>::value) {
                    bsl::print<bsl::V>() << bsl::yellow << "         |\n" << bsl::reset_color;
                }

                if constexpr (bsl::is_same<FIELD_TYPE, bsl::uint64>::value) {
                    bsl::print<bsl::V>() << bsl::yellow << " |\n" << bsl::reset_color;
                }
            }
            else {
                bsl::print<bsl::V>() << bsl::black << "unsupported       " << bsl::reset_color;
                bsl::print<bsl::V>() << bsl::yellow << " |\n" << bsl::reset_color;
            }
        }

        /// <!-- description -->
        ///   @brief Dumps the contents of a missing VMCS register to the
        ///     console. As a reminder, a missing register, is a register
        ///     that we need to keep track of manually and is missing from
        ///     the VMCS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param name the name of the register
        ///   @param type the register's type
        ///   @param value the value of the register
        ///
        constexpr void
        dump_missing_register(
            bsl::string_view const &name,
            bsl::string_view const &type,
            bsl::safe_uintmax const &value) noexcept
        {
            constexpr bsl::safe_uintmax field_width{bsl::to_umax(44)};

            bsl::print<bsl::V>() << bsl::yellow << "| " << bsl::reset_color;
            bsl::print<bsl::V>() << name;

            for (bsl::safe_uintmax i{}; i < field_width - name.length(); ++i) {
                bsl::print<bsl::V>() << ' ';
            }

            bsl::print<bsl::V>() << bsl::yellow << " | " << bsl::reset_color;
            bsl::print<bsl::V>() << type;
            bsl::print<bsl::V>() << bsl::yellow << " | " << bsl::reset_color;

            if (value.is_zero()) {
                bsl::print<bsl::V>() << bsl::black << bsl::hex(value) << bsl::reset_color;
            }
            else {
                bsl::print<bsl::V>() << bsl::hex(value);
            }

            bsl::print<bsl::V>() << bsl::yellow << " |\n" << bsl::reset_color;
        }

        /// <!-- description -->
        ///   @brief Dumps the contents of the VPS to the console
        ///
        /// <!-- inputs/outputs -->
        ///   @tparam TLS_CONCEPT defines the type of TLS block to use
        ///   @param tls the current TLS block
        ///
        template<typename TLS_CONCEPT>
        constexpr void
        dump(TLS_CONCEPT &tls) &noexcept
        {
            /// TODO:
            /// - Right now, we check for unsupported by reading a field
            ///   that might not exist, and if we get an error, we report
            ///   unsupported. This causes a write to the VMCS with an
            ///   error code, which is then logged forever, which could be
            ///   misleading if you happen to dump the same VPS more than
            ///   once. Instead, we really need some detection logic for
            ///   the fields that do not exist.
            /// - Remove the quiet versions of the intrinsics are they
            ///   are not needed once you clean this up.
            /// - Remove the extra read logic from the dump_vmcs_field code and
            ///   use read instead.
            ///

            constexpr bsl::string_view type_64bit_m{"64-bit M"};
            constexpr bsl::string_view type_16bit_c{"16-bit C"};
            constexpr bsl::string_view type_16bit_g{"16-bit G"};
            constexpr bsl::string_view type_16bit_h{"16-bit H"};
            constexpr bsl::string_view type_64bit_c{"64-bit C"};
            constexpr bsl::string_view type_64bit_r{"64-bit R"};
            constexpr bsl::string_view type_64bit_g{"64-bit G"};
            constexpr bsl::string_view type_64bit_h{"64-bit H"};
            constexpr bsl::string_view type_32bit_c{"32-bit C"};
            constexpr bsl::string_view type_32bit_r{"32-bit R"};
            constexpr bsl::string_view type_32bit_g{"32-bit G"};
            constexpr bsl::string_view type_32bit_h{"32-bit H"};

            if constexpr (BSL_DEBUG_LEVEL == bsl::ZERO_UMAX) {
                return;
            }

            if (bsl::unlikely(!m_allocated)) {
                bsl::error() << "invalid vps\n" << bsl::here();
                return;
            }

            if (bsl::unlikely(!this->ensure_this_vps_is_loaded(tls))) {
                bsl::print<bsl::V>() << bsl::here();
                return;
            }

            // clang-format off

            bsl::print<bsl::V>() << bsl::bold_magenta << "VPS" << bsl::reset_color;
            bsl::print<bsl::V>() << " [" << bsl::hex(m_id) << "] ";
            bsl::print<bsl::V>() << bsl::bold_magenta << "Dump: " << bsl::reset_color;
            bsl::print<bsl::V>() << bsl::yellow << bsl::endl;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;
            bsl::print<bsl::V>() << bsl::yellow << "| " << bsl::cyan;
            bsl::print<bsl::V>() << "Field                                        ";
            bsl::print<bsl::V>() << bsl::yellow << "| " << bsl::cyan;
            bsl::print<bsl::V>() << "Type     ";
            bsl::print<bsl::V>() << bsl::yellow << "| " << bsl::cyan;
            bsl::print<bsl::V>() << "Value              ";
            bsl::print<bsl::V>() << bsl::yellow << "|"  << bsl::reset_color << bsl::endl;
            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_missing_register(
                "rax", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_RAX));
            this->dump_missing_register(
                "rbx", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_RBX));
            this->dump_missing_register(
                "rcx", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_RCX));
            this->dump_missing_register(
                "rdx", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_RDX));
            this->dump_missing_register(
                "rbp", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_RBP));
            this->dump_missing_register(
                "rsi", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_RSI));
            this->dump_missing_register(
                "rdi", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_RDI));
            this->dump_missing_register(
                "r8", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_R8));
            this->dump_missing_register(
                "r9", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_R9));
            this->dump_missing_register(
                "r10", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_R10));
            this->dump_missing_register(
                "r11", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_R11));
            this->dump_missing_register(
                "r12", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_R12));
            this->dump_missing_register(
                "r13", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_R13));
            this->dump_missing_register(
                "r14", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_R14));
            this->dump_missing_register(
                "r15", type_64bit_m, m_intrinsic->tls_reg(syscall::TLS_OFFSET_R15));

            this->dump_missing_register(
                "cr2", type_64bit_m, m_vmcs_missing_registers.cr2);
            this->dump_missing_register(
                "dr6", type_64bit_m, m_vmcs_missing_registers.dr6);

            this->dump_missing_register(
                "guest_ia32_star", type_64bit_m, m_vmcs_missing_registers.guest_ia32_star);
            this->dump_missing_register(
                "guest_ia32_lstar", type_64bit_m, m_vmcs_missing_registers.guest_ia32_lstar);
            this->dump_missing_register(
                "guest_ia32_cstar", type_64bit_m, m_vmcs_missing_registers.guest_ia32_cstar);
            this->dump_missing_register(
                "guest_ia32_fmask", type_64bit_m, m_vmcs_missing_registers.guest_ia32_fmask);
            this->dump_missing_register(
                "guest_ia32_kernel_gs_base", type_64bit_m, m_vmcs_missing_registers.guest_ia32_kernel_gs_base);

            this->dump_missing_register(
                "host_ia32_star", type_64bit_m, m_vmcs_missing_registers.host_ia32_star);
            this->dump_missing_register(
                "host_ia32_lstar", type_64bit_m, m_vmcs_missing_registers.host_ia32_lstar);
            this->dump_missing_register(
                "host_ia32_cstar", type_64bit_m, m_vmcs_missing_registers.host_ia32_cstar);
            this->dump_missing_register(
                "host_ia32_fmask", type_64bit_m, m_vmcs_missing_registers.host_ia32_fmask);
            this->dump_missing_register(
                "host_ia32_kernel_gs_base", type_64bit_m, m_vmcs_missing_registers.host_ia32_kernel_gs_base);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint32>(
                "vm_instruction_error", type_32bit_r, VMCS_VM_INSTRUCTION_ERROR);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint16>(
                "virtual_processor_identifier", type_16bit_c, VMCS_VIRTUAL_PROCESSOR_IDENTIFIER);
            this->dump_vmcs_field<bsl::uint16>(
                "posted_interrupt_notification_vector", type_16bit_c, VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "eptp_index", type_16bit_c, VMCS_EPTP_INDEX);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint16>(
                "guest_es_selector", type_16bit_g, VMCS_GUEST_ES_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "guest_cs_selector", type_16bit_g, VMCS_GUEST_CS_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "guest_ss_selector", type_16bit_g, VMCS_GUEST_SS_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "guest_ds_selector", type_16bit_g, VMCS_GUEST_DS_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "guest_fs_selector", type_16bit_g, VMCS_GUEST_FS_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "guest_gs_selector", type_16bit_g, VMCS_GUEST_GS_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "guest_ldtr_selector", type_16bit_g, VMCS_GUEST_LDTR_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "guest_tr_selector", type_16bit_g, VMCS_GUEST_TR_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "guest_interrupt_status", type_16bit_g, VMCS_GUEST_INTERRUPT_STATUS);
            this->dump_vmcs_field<bsl::uint16>(
                "pml_index", type_16bit_g, VMCS_PML_INDEX);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint16>(
                "host_es_selector", type_16bit_h, VMCS_HOST_ES_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "host_cs_selector", type_16bit_h, VMCS_HOST_CS_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "host_ss_selector", type_16bit_h, VMCS_HOST_SS_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "host_ds_selector", type_16bit_h, VMCS_HOST_DS_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "host_fs_selector", type_16bit_h, VMCS_HOST_FS_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "host_gs_selector", type_16bit_h, VMCS_HOST_GS_SELECTOR);
            this->dump_vmcs_field<bsl::uint16>(
                "host_tr_selector", type_16bit_h, VMCS_HOST_TR_SELECTOR);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint64>(
                "address_of_io_bitmap_a", type_64bit_c, VMCS_ADDRESS_OF_IO_BITMAP_A);
            this->dump_vmcs_field<bsl::uint64>(
                "address_of_io_bitmap_b", type_64bit_c, VMCS_ADDRESS_OF_IO_BITMAP_B);
            this->dump_vmcs_field<bsl::uint64>(
                "address_of_msr_bitmaps", type_64bit_c, VMCS_ADDRESS_OF_MSR_BITMAPS);
            this->dump_vmcs_field<bsl::uint64>(
                "vmexit_msr_store_address", type_64bit_c, VMCS_VMEXIT_MSR_STORE_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "vmexit_msr_load_address", type_64bit_c, VMCS_VMEXIT_MSR_LOAD_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "vmentry_msr_load_address", type_64bit_c, VMCS_VMENTRY_MSR_LOAD_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "executive_vmcs_pointer", type_64bit_c, VMCS_EXECUTIVE_VMCS_POINTER);
            this->dump_vmcs_field<bsl::uint64>(
                "pml_address", type_64bit_c, VMCS_PML_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "tsc_offset", type_64bit_c, VMCS_TSC_OFFSET);
            this->dump_vmcs_field<bsl::uint64>(
                "virtual_apic_address", type_64bit_c, VMCS_VIRTUAL_APIC_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "apic_access_address", type_64bit_c, VMCS_APIC_ACCESS_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "posted_interrupt_descriptor_address", type_64bit_c, VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "vm_function_controls", type_64bit_c, VMCS_VM_FUNCTION_CONTROLS);
            this->dump_vmcs_field<bsl::uint64>(
                "ept_pointer", type_64bit_c, VMCS_EPT_POINTER);
            this->dump_vmcs_field<bsl::uint64>(
                "eoi_exit_bitmap0", type_64bit_c, VMCS_EOI_EXIT_BITMAP0);
            this->dump_vmcs_field<bsl::uint64>(
                "eoi_exit_bitmap1", type_64bit_c, VMCS_EOI_EXIT_BITMAP1);
            this->dump_vmcs_field<bsl::uint64>(
                "eoi_exit_bitmap2", type_64bit_c, VMCS_EOI_EXIT_BITMAP2);
            this->dump_vmcs_field<bsl::uint64>(
                "eoi_exit_bitmap3", type_64bit_c, VMCS_EOI_EXIT_BITMAP3);
            this->dump_vmcs_field<bsl::uint64>(
                "eptp_list_address", type_64bit_c, VMCS_EPTP_LIST_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "vmread_bitmap_address", type_64bit_c, VMCS_VMREAD_BITMAP_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "vmwrite_bitmap_address", type_64bit_c, VMCS_VMWRITE_BITMAP_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "virt_exception_information_address", type_64bit_c, VMCS_VIRT_EXCEPTION_INFORMATION_ADDRESS);
            this->dump_vmcs_field<bsl::uint64>(
                "xss_exiting_bitmap", type_64bit_c, VMCS_XSS_EXITING_BITMAP);
            this->dump_vmcs_field<bsl::uint64>(
                "encls_exiting_bitmap", type_64bit_c, VMCS_ENCLS_EXITING_BITMAP);
            this->dump_vmcs_field<bsl::uint64>(
                "sub_page_permission_table_pointer", type_64bit_c, VMCS_SUB_PAGE_PERMISSION_TABLE_POINTER);
            this->dump_vmcs_field<bsl::uint64>(
                "tls_multiplier", type_64bit_c, VMCS_TLS_MULTIPLIER);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint64>(
                "guest_physical_address", type_64bit_r, VMCS_GUEST_PHYSICAL_ADDRESS);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint64>(
                "vmcs_link_pointer", type_64bit_g, VMCS_VMCS_LINK_POINTER);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_ia32_debugctl", type_64bit_g, VMCS_GUEST_IA32_DEBUGCTL);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_ia32_pat", type_64bit_g, VMCS_GUEST_IA32_PAT);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_ia32_efer", type_64bit_g, VMCS_GUEST_IA32_EFER);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_ia32_perf_global_ctrl", type_64bit_g, VMCS_GUEST_IA32_PERF_GLOBAL_CTRL);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_pdpte0", type_64bit_g, VMCS_GUEST_PDPTE0);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_pdpte1", type_64bit_g, VMCS_GUEST_PDPTE1);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_pdpte2", type_64bit_g, VMCS_GUEST_PDPTE2);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_pdpte3", type_64bit_g, VMCS_GUEST_PDPTE3);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_ia32_bndcfgs", type_64bit_g, VMCS_GUEST_IA32_BNDCFGS);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_rtit_ctl", type_64bit_g, VMCS_GUEST_RTIT_CTL);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint64>(
                "host_ia32_pat", type_64bit_h, VMCS_HOST_IA32_PAT);
            this->dump_vmcs_field<bsl::uint64>(
                "host_ia32_efer", type_64bit_h, VMCS_HOST_IA32_EFER);
            this->dump_vmcs_field<bsl::uint64>(
                "host_ia32_perf_global_ctrl", type_64bit_h, VMCS_HOST_IA32_PERF_GLOBAL_CTRL);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint32>(
                "pin_based_vm_execution_ctls", type_32bit_c, VMCS_PIN_BASED_VM_EXECUTION_CTLS);
            this->dump_vmcs_field<bsl::uint32>(
                "primary_proc_based_vm_execution_ctls", type_32bit_c, VMCS_PRIMARY_PROC_BASED_VM_EXECUTION_CTLS);
            this->dump_vmcs_field<bsl::uint32>(
                "exception_bitmap", type_32bit_c, VMCS_EXCEPTION_BITMAP);
            this->dump_vmcs_field<bsl::uint32>(
                "page_fault_error_code_mask", type_32bit_c, VMCS_PAGE_FAULT_ERROR_CODE_MASK);
            this->dump_vmcs_field<bsl::uint32>(
                "page_fault_error_code_match", type_32bit_c, VMCS_PAGE_FAULT_ERROR_CODE_MATCH);
            this->dump_vmcs_field<bsl::uint32>(
                "cr3_target_count", type_32bit_c, VMCS_CR3_TARGET_COUNT);
            this->dump_vmcs_field<bsl::uint32>(
                "vmexit_ctls", type_32bit_c, VMCS_VMEXIT_CTLS);
            this->dump_vmcs_field<bsl::uint32>(
                "vmexit_msr_store_count", type_32bit_c, VMCS_VMEXIT_MSR_STORE_COUNT);
            this->dump_vmcs_field<bsl::uint32>(
                "vmexit_msr_load_count", type_32bit_c, VMCS_VMEXIT_MSR_LOAD_COUNT);
            this->dump_vmcs_field<bsl::uint32>(
                "vmentry_ctls", type_32bit_c, VMCS_VMENTRY_CTLS);
            this->dump_vmcs_field<bsl::uint32>(
                "vmentry_msr_load_count", type_32bit_c, VMCS_VMENTRY_MSR_LOAD_COUNT);
            this->dump_vmcs_field<bsl::uint32>(
                "vmentry_interrupt_information_field", type_32bit_c, VMCS_VMENTRY_INTERRUPT_INFORMATION_FIELD);
            this->dump_vmcs_field<bsl::uint32>(
                "vmentry_exception_error_code", type_32bit_c, VMCS_VMENTRY_EXCEPTION_ERROR_CODE);
            this->dump_vmcs_field<bsl::uint32>(
                "vmentry_instruction_length", type_32bit_c, VMCS_VMENTRY_INSTRUCTION_LENGTH);
            this->dump_vmcs_field<bsl::uint32>(
                "tpr_threshold", type_32bit_c, VMCS_TPR_THRESHOLD);
            this->dump_vmcs_field<bsl::uint32>(
                "secondary_proc_based_vm_execution_ctls", type_32bit_c, VMCS_SECONDARY_PROC_BASED_VM_EXECUTION_CTLS);
            this->dump_vmcs_field<bsl::uint32>(
                "ple_gap", type_32bit_c, VMCS_PLE_GAP);
            this->dump_vmcs_field<bsl::uint32>(
                "ple_window", type_32bit_c, VMCS_PLE_WINDOW);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint32>(
                "exit_reason", type_32bit_r, VMCS_EXIT_REASON);
            this->dump_vmcs_field<bsl::uint32>(
                "vmexit_interruption_information", type_32bit_r, VMCS_VMEXIT_INTERRUPTION_INFORMATION);
            this->dump_vmcs_field<bsl::uint32>(
                "vmexit_interruption_error_code", type_32bit_r, VMCS_VMEXIT_INTERRUPTION_ERROR_CODE);
            this->dump_vmcs_field<bsl::uint32>(
                "idt_vectoring_information_field", type_32bit_r, VMCS_IDT_VECTORING_INFORMATION_FIELD);
            this->dump_vmcs_field<bsl::uint32>(
                "idt_vectoring_error_code", type_32bit_r, VMCS_IDT_VECTORING_ERROR_CODE);
            this->dump_vmcs_field<bsl::uint32>(
                "vmexit_instruction_length", type_32bit_r, VMCS_VMEXIT_INSTRUCTION_LENGTH);
            this->dump_vmcs_field<bsl::uint32>(
                "vmexit_instruction_information", type_32bit_r, VMCS_VMEXIT_INSTRUCTION_INFORMATION);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint32>(
                "guest_es_limit", type_32bit_g, VMCS_GUEST_ES_LIMIT);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_cs_limit", type_32bit_g, VMCS_GUEST_CS_LIMIT);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_ss_limit", type_32bit_g, VMCS_GUEST_SS_LIMIT);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_ds_limit", type_32bit_g, VMCS_GUEST_DS_LIMIT);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_fs_limit", type_32bit_g, VMCS_GUEST_FS_LIMIT);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_gs_limit", type_32bit_g, VMCS_GUEST_GS_LIMIT);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_ldtr_limit", type_32bit_g, VMCS_GUEST_LDTR_LIMIT);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_tr_limit", type_32bit_g, VMCS_GUEST_TR_LIMIT);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_gdtr_limit", type_32bit_g, VMCS_GUEST_GDTR_LIMIT);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_idtr_limit", type_32bit_g, VMCS_GUEST_IDTR_LIMIT);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_es_access_rights", type_32bit_g, VMCS_GUEST_ES_ACCESS_RIGHTS);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_cs_access_rights", type_32bit_g, VMCS_GUEST_CS_ACCESS_RIGHTS);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_ss_access_rights", type_32bit_g, VMCS_GUEST_SS_ACCESS_RIGHTS);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_ds_access_rights", type_32bit_g, VMCS_GUEST_DS_ACCESS_RIGHTS);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_fs_access_rights", type_32bit_g, VMCS_GUEST_FS_ACCESS_RIGHTS);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_gs_access_rights", type_32bit_g, VMCS_GUEST_GS_ACCESS_RIGHTS);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_ldtr_access_rights", type_32bit_g, VMCS_GUEST_LDTR_ACCESS_RIGHTS);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_tr_access_rights", type_32bit_g, VMCS_GUEST_TR_ACCESS_RIGHTS);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_interruptibility_state", type_32bit_g, VMCS_GUEST_INTERRUPTIBILITY_STATE);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_activity_state", type_32bit_g, VMCS_GUEST_ACTIVITY_STATE);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_smbase", type_32bit_g, VMCS_GUEST_SMBASE);
            this->dump_vmcs_field<bsl::uint32>(
                "guest_ia32_sysenter_cs", type_32bit_g, VMCS_GUEST_IA32_SYSENTER_CS);
            this->dump_vmcs_field<bsl::uint32>(
                "vmx_preemption_timer_value", type_32bit_g, VMCS_VMX_PREEMPTION_TIMER_VALUE);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint32>(
                "host_ia32_sysenter_cs", type_32bit_h, VMCS_HOST_IA32_SYSENTER_CS);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint64>(
                "cr0_guest_host_mask", type_64bit_c, VMCS_CR0_GUEST_HOST_MASK);
            this->dump_vmcs_field<bsl::uint64>(
                "cr4_guest_host_mask", type_64bit_c, VMCS_CR4_GUEST_HOST_MASK);
            this->dump_vmcs_field<bsl::uint64>(
                "cr0_read_shadow", type_64bit_c, VMCS_CR0_READ_SHADOW);
            this->dump_vmcs_field<bsl::uint64>(
                "cr4_read_shadow", type_64bit_c, VMCS_CR4_READ_SHADOW);
            this->dump_vmcs_field<bsl::uint64>(
                "cr3_target_value0", type_64bit_c, VMCS_CR3_TARGET_VALUE0);
            this->dump_vmcs_field<bsl::uint64>(
                "cr3_target_value1", type_64bit_c, VMCS_CR3_TARGET_VALUE1);
            this->dump_vmcs_field<bsl::uint64>(
                "cr3_target_value2", type_64bit_c, VMCS_CR3_TARGET_VALUE2);
            this->dump_vmcs_field<bsl::uint64>(
                "cr3_target_value3", type_64bit_c, VMCS_CR3_TARGET_VALUE3);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint64>(
                "exit_qualification", type_64bit_r, VMCS_EXIT_QUALIFICATION);
            this->dump_vmcs_field<bsl::uint64>(
                "io_rcx", type_64bit_r, VMCS_IO_RCX);
            this->dump_vmcs_field<bsl::uint64>(
                "io_rsi", type_64bit_r, VMCS_IO_RSI);
            this->dump_vmcs_field<bsl::uint64>(
                "io_rdi", type_64bit_r, VMCS_IO_RDI);
            this->dump_vmcs_field<bsl::uint64>(
                "io_rip", type_64bit_r, VMCS_IO_RIP);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_linear_address", type_64bit_r, VMCS_GUEST_LINEAR_ADDRESS);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint64>(
                "guest_cr0", type_64bit_g, VMCS_GUEST_CR0);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_cr3", type_64bit_g, VMCS_GUEST_CR3);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_cr4", type_64bit_g, VMCS_GUEST_CR4);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_es_base", type_64bit_g, VMCS_GUEST_ES_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_cs_base", type_64bit_g, VMCS_GUEST_CS_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_ss_base", type_64bit_g, VMCS_GUEST_SS_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_ds_base", type_64bit_g, VMCS_GUEST_DS_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_fs_base", type_64bit_g, VMCS_GUEST_FS_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_gs_base", type_64bit_g, VMCS_GUEST_GS_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_ldtr_base", type_64bit_g, VMCS_GUEST_LDTR_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_tr_base", type_64bit_g, VMCS_GUEST_TR_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_gdtr_base", type_64bit_g, VMCS_GUEST_GDTR_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_idtr_base", type_64bit_g, VMCS_GUEST_IDTR_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_dr7", type_64bit_g, VMCS_GUEST_DR7);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_rsp", type_64bit_g, VMCS_GUEST_RSP);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_rip", type_64bit_g, VMCS_GUEST_RIP);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_rflags", type_64bit_g, VMCS_GUEST_RFLAGS);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_pending_debug_exceptions", type_64bit_g, VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_ia32_sysenter_esp", type_64bit_g, VMCS_GUEST_IA32_SYSENTER_ESP);
            this->dump_vmcs_field<bsl::uint64>(
                "guest_ia32_sysenter_eip", type_64bit_g, VMCS_GUEST_IA32_SYSENTER_EIP);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;

            this->dump_vmcs_field<bsl::uint64>(
                "host_cr0", type_64bit_h, VMCS_HOST_CR0);
            this->dump_vmcs_field<bsl::uint64>(
                "host_cr3", type_64bit_h, VMCS_HOST_CR3);
            this->dump_vmcs_field<bsl::uint64>(
                "host_cr4", type_64bit_h, VMCS_HOST_CR4);
            this->dump_vmcs_field<bsl::uint64>(
                "host_fs_base", type_64bit_h, VMCS_HOST_FS_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "host_gs_base", type_64bit_h, VMCS_HOST_GS_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "host_tr_base", type_64bit_h, VMCS_HOST_TR_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "host_gdtr_base", type_64bit_h, VMCS_HOST_GDTR_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "host_idtr_base", type_64bit_h, VMCS_HOST_IDTR_BASE);
            this->dump_vmcs_field<bsl::uint64>(
                "host_ia32_sysenter_esp", type_64bit_h, VMCS_HOST_IA32_SYSENTER_ESP);
            this->dump_vmcs_field<bsl::uint64>(
                "host_ia32_sysenter_eip", type_64bit_h, VMCS_HOST_IA32_SYSENTER_EIP);
            this->dump_vmcs_field<bsl::uint64>(
                "host_rsp", type_64bit_h, VMCS_HOST_RSP);
            this->dump_vmcs_field<bsl::uint64>(
                "host_rip", type_64bit_h, VMCS_HOST_RIP);

            bsl::print<bsl::V>() << bsl::yellow;
            bsl::print<bsl::V>() << "+---------------------------------------";
            bsl::print<bsl::V>() << "---------------------------------------+";
            bsl::print<bsl::V>() << bsl::reset_color << bsl::endl;
        }
    };
}

#endif
