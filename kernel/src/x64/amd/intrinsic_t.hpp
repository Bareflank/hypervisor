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

#ifndef INTRINSIC_HPP
#define INTRINSIC_HPP

#include <bf_constants.hpp>
#include <intrinsic_invlpg.hpp>
#include <intrinsic_invlpga.hpp>
#include <intrinsic_rdmsr.hpp>
#include <intrinsic_set_cr3.hpp>
#include <intrinsic_set_tls_reg.hpp>
#include <intrinsic_set_tp.hpp>
#include <intrinsic_tls_reg.hpp>
#include <intrinsic_vmrun.hpp>
#include <intrinsic_wrmsr.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Provides raw access to intrinsics. Instead of using global
    ///     functions, the intrinsics class provides a means for the rest of
    ///     the kernel to mock the intrinsics when needed during unit testing.
    ///
    class intrinsic_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Invalidates TLB entries given an address and an ASID.
        ///     If the ASID is set to 0, an extension address is invalidated.
        ///     If the ASID is non-0, a guest address is invalidated using the
        ///     ASID. On AMD, this function does not invalidate an entire guest
        ///     VS (the vs_t must be used for that operation).
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr the address to invalidate.
        ///   @param asid the ASID (as defined by AMD) to flush.
        ///
        static constexpr void
        tlb_flush(
            bsl::safe_u64 const &addr, bsl::safe_u16 const &asid = syscall::BF_INVALID_ID) noexcept
        {
            bsl::expects(addr.is_valid_and_checked());
            bsl::expects(addr.is_pos());
            bsl::expects(asid.is_valid_and_checked());
            bsl::expects(asid.is_pos());

            if (syscall::BF_INVALID_ID == asid) {
                return intrinsic_invlpg(addr.get());
            }

            return intrinsic_invlpga(addr.get(), bsl::to_u64(asid).get());
        }

        /// <!-- description -->
        ///   @brief Sets the RPT pointer
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set the RPT pointer to
        ///
        static constexpr void
        set_rpt(bsl::safe_u64 const &val) noexcept
        {
            intrinsic_set_cr3(val.get());
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
            intrinsic_set_tp(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of a requested TLS register
        ///
        /// <!-- inputs/outputs -->
        ///   @param reg the TLS register to get
        ///   @return Returns the value of a requested TLS register
        ///
        [[nodiscard]] static constexpr auto
        tls_reg(bsl::safe_u64 const &reg) noexcept -> bsl::safe_u64
        {
            return bsl::to_u64(intrinsic_tls_reg(reg.get()));
        }

        /// <!-- description -->
        ///   @brief Sets the value of a requested TLS register
        ///
        /// <!-- inputs/outputs -->
        ///   @param reg the TLS register to set
        ///   @param val the value to set the TLS register to
        ///
        static constexpr void
        set_tls_reg(bsl::safe_u64 const &reg, bsl::safe_u64 const &val) noexcept
        {
            intrinsic_set_tls_reg(reg.get(), val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr the MSR to read from
        ///   @return Returns the value of requested MSR
        ///
        [[nodiscard]] static constexpr auto
        rdmsr(bsl::safe_u32 const &msr) noexcept -> bsl::safe_u64
        {
            bsl::safe_u64 mut_val{};

            auto const ret{intrinsic_rdmsr(msr.get(), mut_val.data())};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "rdmsr failed for msr "    // --
                             << bsl::hex(msr)              // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::safe_u64::failure();
            }

            return mut_val;
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
        [[nodiscard]] static constexpr auto
        wrmsr(bsl::safe_u32 const &msr, bsl::safe_u64 const &val) noexcept -> bsl::errc_type
        {
            auto const ret{intrinsic_wrmsr(msr.get(), val.get())};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "wrmsr failed for msr "    // --
                             << bsl::hex(msr)              // --
                             << " with value "             // --
                             << bsl::hex(val)              // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Executes the VMRun instruction. When this function returns
        ///     a "VMExit" has occurred and must be handled.
        ///
        /// <!-- inputs/outputs -->
        ///   @param pmut_guest_vmcb a pointer to the guest VMCB
        ///   @param guest_vmcb_phys the physical address of the guest VMCB
        ///   @param pmut_host_vmcb a pointer to the host VMCB
        ///   @param host_vmcb_phys the physical address of the host VMCB
        ///   @param pmut_missing_registers a pointer to the missing registers
        ///   @return Returns the exit reason associated with the VMExit
        ///
        [[nodiscard]] static constexpr auto
        vmrun(
            void *const pmut_guest_vmcb,
            bsl::safe_umx const &guest_vmcb_phys,
            void *const pmut_host_vmcb,
            bsl::safe_umx const &host_vmcb_phys,
            void *const pmut_missing_registers) noexcept -> bsl::safe_umx
        {
            bsl::uintmx const exit_reason{intrinsic_vmrun(
                pmut_guest_vmcb,
                guest_vmcb_phys.get(),
                pmut_host_vmcb,
                host_vmcb_phys.get(),
                pmut_missing_registers)};

            return bsl::safe_umx{exit_reason};
        }
    };
}

#endif
