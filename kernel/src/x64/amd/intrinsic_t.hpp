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
#include <tlb_flush_type_t.hpp>

#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/expects.hpp>
#include <bsl/safe_integral.hpp>

namespace mk
{
    /// <!-- description -->
    ///   @brief Implements intrinsic_t::invlpg
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void intrinsic_invlpg(bsl::uint64 const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::invlpga
    ///
    /// <!-- inputs/outputs -->
    ///   @param addr n/a
    ///   @param asid n/a
    ///
    extern "C" void intrinsic_invlpga(bsl::uint64 const addr, bsl::uint64 const asid) noexcept;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::set_cr3
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void intrinsic_set_cr3(bsl::uint64 const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::set_tp
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void intrinsic_set_tp(bsl::uint64 const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::tls_reg
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto intrinsic_tls_reg(bsl::uint64 const reg) noexcept -> bsl::uint64;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::set_tls_reg
    ///
    /// <!-- inputs/outputs -->
    ///   @param reg n/a
    ///   @param val n/a
    ///
    extern "C" void intrinsic_set_tls_reg(bsl::uint64 const reg, bsl::uint64 const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::rdmsr
    ///
    /// <!-- inputs/outputs -->
    ///   @param msr n/a
    ///   @param pmut_val n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    intrinsic_rdmsr(bsl::uint32 const msr, bsl::uint64 *const pmut_val) noexcept -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::wrmsr
    ///
    /// <!-- inputs/outputs -->
    ///   @param msr n/a
    ///   @param val n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    intrinsic_wrmsr(bsl::uint32 const msr, bsl::uint64 const val) noexcept -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Executes the VMRun instruction. When this function returns
    ///     a "VMExit" has occurred and must be handled.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_guest_vmcb a pointer to the guest VMCB to use
    ///   @param guest_vmcb_phys the physical address of the guest VMCB to use
    ///   @param pmut_host_vmcb a pointer to the host VMCB to use
    ///   @param host_vmcb_phys the physical address of the host VMCB to use
    ///   @return Returns the exit reason associated with the VMExit
    ///
    extern "C" [[nodiscard]] auto intrinsic_vmrun(
        void *const pmut_guest_vmcb,
        bsl::uintmx const guest_vmcb_phys,
        void *const pmut_host_vmcb,
        bsl::uintmx const host_vmcb_phys) noexcept -> bsl::uintmx;

    /// @class mk::intrinsic_t
    ///
    /// <!-- description -->
    ///   @brief Provides raw access to intrinsics. Instead of using global
    ///     functions, the intrinsics class provides a means for the rest of
    ///     the kernel to mock the intrinsics when needed during unit testing.
    ///
    class intrinsic_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Invalidates TLB entries given a address
        ///
        /// <!-- inputs/outputs -->
        ///   @param type determines which type of flush to perform
        ///   @param addr the address to invalidate
        ///   @param vmid if set to a valid ID, will flush the address for
        ///     the given VMID as an ASID.
        ///
        static constexpr void
        tlb_flush(
            tlb_flush_type_t const type,
            bsl::safe_u64 const &addr,
            bsl::safe_u16 const &vmid = syscall::BF_INVALID_ID) noexcept
        {
            bsl::expects(addr.is_valid_and_checked());
            bsl::expects(addr.is_pos());
            bsl::expects(vmid.is_valid_and_checked());

            /// NOTE:
            /// - Since we only plan to support Zen 3 and above, for a
            ///   broadcast TLB flush, just use the broadcast TLB flush
            ///   instructions. Don't forget to sync.
            ///

            switch (type) {
                case tlb_flush_type_t::local: {
                    if (syscall::BF_INVALID_ID == vmid) {
                        intrinsic_invlpg(addr.get());
                    }
                    else {
                        intrinsic_invlpga(addr.get(), bsl::to_u64(vmid).get());
                    }

                    break;
                }

                case tlb_flush_type_t::broadcast: {
                    bsl::alert() << "broadcast TLB flush not yet implemented\n" << bsl::here();
                    break;
                }
            }
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
    };
}

#endif
