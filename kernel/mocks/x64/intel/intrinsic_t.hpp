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

#ifndef MOCKS_INTRINSIC_HPP
#define MOCKS_INTRINSIC_HPP

#include <bf_constants.hpp>
#include <vmcs_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unordered_map.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Dummy VMExit function needed by Intel.
    ///
    extern "C" void
    intrinsic_vmexit(void) noexcept    // NOLINT
    {}

    /// <!-- description -->
    ///   @brief Provides raw access to intrinsics. Instead of using global
    ///     functions, the intrinsics class provides a means for the rest of
    ///     the kernel to mock the intrinsics when needed during unit testing.
    ///
    class intrinsic_t final
    {
        /// @brief stores values associated with the TLS
        bsl::unordered_map<bsl::safe_u64, bsl::safe_u64> m_tlss{};
        /// @brief stores values associated with MSRs
        bsl::unordered_map<bsl::safe_u32, bsl::safe_u64> m_msrs{};
        /// @brief stores values associated with the VMCS
        bsl::unordered_map<bsl::safe_u64, bsl::safe_u64> m_vmcs{};

    public:
        /// <!-- description -->
        ///   @brief Invalidates TLB entries given an address and a VPID.
        ///     If the VPID is set to BF_INVALID_ID, an extension address
        ///     is invalidated. If the VPID is valid, a guest address is
        ///     invalidated using the VPID. If the address is valid, the
        ///     address is invalidated for the guest. If the address is
        ///     0, the entire VM is invalidated using the currently loaded
        ///     VS's EPTP. If EPTP is never set by the extension, all VMs
        ///     are flushed.
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to invalidate.
        ///   @param vpid the VPID (as defined by Intel) to flush.
        ///
        static constexpr void
        tlb_flush(
            bsl::safe_u64 const &addr, bsl::safe_u16 const &vpid = syscall::BF_INVALID_ID) noexcept
        {
            bsl::expects(addr.is_valid_and_checked());
            bsl::expects(vpid.is_valid_and_checked());
        }

        /// <!-- description -->
        ///   @brief Returns the value of ES
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of ES
        ///
        [[nodiscard]] static constexpr auto
        es_selector() noexcept -> bsl::safe_u16
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of CS
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of CS
        ///
        [[nodiscard]] static constexpr auto
        cs_selector() noexcept -> bsl::safe_u16
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of SS
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of SS
        ///
        [[nodiscard]] static constexpr auto
        ss_selector() noexcept -> bsl::safe_u16
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of DS
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of DS
        ///
        [[nodiscard]] static constexpr auto
        ds_selector() noexcept -> bsl::safe_u16
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of FS
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of FS
        ///
        [[nodiscard]] static constexpr auto
        fs_selector() noexcept -> bsl::safe_u16
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of GS
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of GS
        ///
        [[nodiscard]] static constexpr auto
        gs_selector() noexcept -> bsl::safe_u16
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of TR
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of TR
        ///
        [[nodiscard]] static constexpr auto
        tr_selector() noexcept -> bsl::safe_u16
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of CR0
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of CR0
        ///
        [[nodiscard]] static constexpr auto
        cr0() noexcept -> bsl::safe_u64
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of CR3
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of CR3
        ///
        [[nodiscard]] static constexpr auto
        cr3() noexcept -> bsl::safe_u64
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Returns the value of CR4
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of CR4
        ///
        [[nodiscard]] static constexpr auto
        cr4() noexcept -> bsl::safe_u64
        {
            return {};
        }

        /// <!-- description -->
        ///   @brief Sets the value of CR3
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set CR3 to
        ///
        static constexpr void
        set_rpt(bsl::safe_u64 const &val) noexcept
        {
            bsl::discard(val);
        }

        /// <!-- description -->
        ///   @brief Sets the value of tp (TLS pointer)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set tp (TLS pointer) to
        ///
        static constexpr void
        set_tp(bsl::safe_u64 const &val) noexcept
        {
            bsl::discard(val);
        }

        /// <!-- description -->
        ///   @brief Returns the value of a requested TLS register
        ///
        /// <!-- inputs/outputs -->
        ///   @param reg the TLS register to get
        ///   @return Returns the value of a requested TLS register
        ///
        [[nodiscard]] constexpr auto
        tls_reg(bsl::safe_u64 const &reg) const noexcept -> bsl::safe_u64
        {
            return m_tlss.at(reg);
        }

        /// <!-- description -->
        ///   @brief Sets the value of a requested TLS register
        ///
        /// <!-- inputs/outputs -->
        ///   @param reg the TLS register to set
        ///   @param val the value to set the TLS register to
        ///
        constexpr void
        set_tls_reg(bsl::safe_u64 const &reg, bsl::safe_u64 const &val) noexcept
        {
            bsl::expects(reg.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            m_tlss.at(reg) = val;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr the MSR to read from
        ///   @return Returns the value of requested MSR
        ///
        [[nodiscard]] constexpr auto
        rdmsr(bsl::safe_u32 const &msr) const noexcept -> bsl::safe_u64
        {
            bsl::expects(msr.is_valid_and_checked());

            if (msr == bsl::safe_u32::max_value()) {
                return bsl::safe_u64::failure();
            }

            return m_msrs.at(msr);
        }

        /// <!-- description -->
        ///   @brief Sets the value of requested MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr the MSR to write to
        ///   @param val the value to set the MSR to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        wrmsr(bsl::safe_u32 const &msr, bsl::safe_u64 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(msr.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            if (msr == bsl::safe_u32::max_value()) {
                return bsl::errc_failure;
            }

            m_msrs.at(msr) = val;
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Loads a VMCS given a pointer to the physical address
        ///     of the VMCS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phys a pointer to the physical address of the VMCS to
        ///     load.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        // NOLINTNEXTLINE(bsl-identifier-typographically-unambiguous)
        vmld(void const *const phys) noexcept -> bsl::errc_type
        {
            bsl::discard(phys);
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Clears a VMCS given a pointer to the physical address
        ///     of the VMCS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phys a pointer to the physical address of the VMCS to
        ///     clear.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmcl(void const *const phys) noexcept -> bsl::errc_type
        {
            bsl::discard(phys);
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 16 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 16 bit VMCS field to read
        ///   @param pmut_val the value to store the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vmrd16(bsl::safe_u64 const &field, bsl::uint16 *const pmut_val) const noexcept
            -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());

            if (field == bsl::safe_u64::max_value()) {
                return bsl::errc_failure;
            }

            if (field == VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR) {
                return bsl::errc_failure;
            }

            *pmut_val = bsl::to_u16(m_vmcs.at(field)).get();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 16 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 16 bit VMCS field to read
        ///   @return Returns the 16 bit VMCS field on success. On failure,
        ///     returns bsl::uint16::failure().
        ///
        [[nodiscard]] constexpr auto
        vmrd16(bsl::safe_u64 const &field) const noexcept -> bsl::safe_u16
        {
            bsl::expects(field.is_valid_and_checked());

            if (field == bsl::safe_u64::max_value()) {
                return bsl::safe_u16::failure();
            }

            if (field == VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR) {
                return bsl::safe_u16::failure();
            }

            return bsl::to_u16(m_vmcs.at(field));
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 32 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 32 bit VMCS field to read
        ///   @param pmut_val the value to store the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vmrd32(bsl::safe_u64 const &field, bsl::uint32 *const pmut_val) const noexcept
            -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());

            if (field == bsl::safe_u64::max_value()) {
                return bsl::errc_failure;
            }

            if (field == VMCS_VMX_PREEMPTION_TIMER_VALUE) {
                return bsl::errc_failure;
            }

            *pmut_val = bsl::to_u32(m_vmcs.at(field)).get();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 32 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 32 bit VMCS field to read
        ///   @return Returns the 32 bit VMCS field on success. On failure,
        ///     returns bsl::uint32::failure().
        ///
        [[nodiscard]] constexpr auto
        vmrd32(bsl::safe_u64 const &field) const noexcept -> bsl::safe_u32
        {
            bsl::expects(field.is_valid_and_checked());

            if (field == bsl::safe_u64::max_value()) {
                return bsl::safe_u32::failure();
            }

            if (field == VMCS_VMX_PREEMPTION_TIMER_VALUE) {
                return bsl::safe_u32::failure();
            }

            return bsl::to_u32(m_vmcs.at(field));
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 64 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 64 bit VMCS field to read
        ///   @param pmut_val the value to store the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vmrd64(bsl::safe_u64 const &field, bsl::uint64 *const pmut_val) const noexcept
            -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());

            if (field == bsl::safe_u64::max_value()) {
                return bsl::errc_failure;
            }

            if (field == VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR) {
                return bsl::errc_failure;
            }

            if (field == VMCS_VMX_PREEMPTION_TIMER_VALUE) {
                return bsl::errc_failure;
            }

            if (field == VMCS_TSC_MULTIPLIER) {
                return bsl::errc_failure;
            }

            *pmut_val = bsl::to_u64(m_vmcs.at(field)).get();
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 64 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 64 bit VMCS field to read
        ///   @return Returns the 64 bit VMCS field on success. On failure,
        ///     returns bsl::uint64::failure().
        ///
        [[nodiscard]] constexpr auto
        vmrd64(bsl::safe_u64 const &field) const noexcept -> bsl::safe_u64
        {
            bsl::expects(field.is_valid_and_checked());

            if (field == bsl::safe_u64::max_value()) {
                return bsl::safe_u64::failure();
            }

            if (field == VMCS_TSC_MULTIPLIER) {
                return bsl::safe_u64::failure();
            }

            return bsl::to_u64(m_vmcs.at(field));
        }

        /// <!-- description -->
        ///   @brief Sets the value of requested 16 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 16 bit VMCS field to write to
        ///   @param val the value to set the 16 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vmwr16(bsl::safe_u64 const &field, bsl::safe_u16 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            if (field == bsl::safe_u64::max_value()) {
                return bsl::errc_failure;
            }

            m_vmcs.at(field) = bsl::to_u64(val);
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the value of requested 32 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 32 bit VMCS field to write to
        ///   @param val the value to set the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vmwr32(bsl::safe_u64 const &field, bsl::safe_u32 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            if (field == bsl::safe_u64::max_value()) {
                return bsl::errc_failure;
            }

            m_vmcs.at(field) = bsl::to_u64(val);
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the value of requested 64 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 64 bit VMCS field to write to
        ///   @param val the value to set the 64 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        vmwr64(bsl::safe_u64 const &field, bsl::safe_u64 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            if (field == bsl::safe_u64::max_value()) {
                return bsl::errc_failure;
            }

            m_vmcs.at(field) = bsl::to_u64(val);
            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the value of requested 64 bit VMCS field (function
        ///     version)
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 64 bit VMCS field to write to
        ///   @param pmut_func the function value to set the 64 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmwrfunc(bsl::safe_u64 const &field, void (*const pmut_func)() noexcept) noexcept
            -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());
            bsl::discard(pmut_func);

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Executes the VMLaunch/VMResume instructions. When this
        ///     function returns, a "VMExit" has occurred and must be handled.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pmut_missing_registers a pointer to the missing registers
        ///   @return Returns the exit reason associated with the VMExit
        ///
        [[nodiscard]] static constexpr auto
        vmrun(void *const pmut_missing_registers) noexcept -> bsl::safe_umx
        {
            bsl::discard(pmut_missing_registers);
            return {};
        }
    };
}

#endif
