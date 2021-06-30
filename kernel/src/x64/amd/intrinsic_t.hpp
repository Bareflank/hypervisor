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

#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/is_constant_evaluated.hpp>
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
    ///   @brief Implements intrinsic_t::cr3
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto intrinsic_cr3() noexcept -> bsl::uint64;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::set_cr3
    ///
    /// <!-- inputs/outputs -->
    ///   @param val n/a
    ///
    extern "C" void intrinsic_set_cr3(bsl::uint64 const val) noexcept;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::tp
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto intrinsic_tp() noexcept -> bsl::uint64;

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
    ///   @brief Implements intrinsic_t::halt
    ///
    extern "C" void intrinsic_halt() noexcept;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::rdmsr
    ///
    /// <!-- inputs/outputs -->
    ///   @param msr n/a
    ///   @param val n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto intrinsic_rdmsr(bsl::uint32 msr, bsl::uint64 *const val) noexcept
        -> bsl::exit_code;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::wrmsr
    ///
    /// <!-- inputs/outputs -->
    ///   @param msr n/a
    ///   @param val n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto intrinsic_wrmsr(bsl::uint32 msr, bsl::uint64 const val) noexcept
        -> bsl::exit_code;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::invlpga
    ///
    /// <!-- inputs/outputs -->
    ///   @param addr n/a
    ///   @param asid n/a
    ///
    extern "C" void intrinsic_invlpga(bsl::uint64 addr, bsl::uint64 const asid) noexcept;

    /// <!-- description -->
    ///   @brief Executes the VMRun instruction. When this function returns
    ///     a "VMExit" has occurred and must be handled.
    ///
    /// <!-- inputs/outputs -->
    ///   @param guest_vmcb a pointer to the guest VMCB to use
    ///   @param guest_vmcb_phys the physical address of the guest VMCB to use
    ///   @param host_vmcb a pointer to the host VMCB to use
    ///   @param host_vmcb_phys the physical address of the host VMCB to use
    ///   @return Returns the exit reason associated with the VMExit
    ///
    extern "C" [[nodiscard]] auto intrinsic_vmrun(
        void *const guest_vmcb,
        bsl::uintmax const guest_vmcb_phys,
        void *const host_vmcb,
        bsl::uintmax const host_vmcb_phys) noexcept -> bsl::uintmax;

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
        ///   @brief Invalidates TLB entries given a virtual address
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the virtual address to invalidate
        ///
        static constexpr void
        invlpg(bsl::safe_uint64 const &val) noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val "    // --
                             << bsl::hex(val)     // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return;
            }

            intrinsic_invlpg(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of CR3
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of CR3
        ///
        [[nodiscard]] static constexpr auto
        cr3() noexcept -> bsl::safe_uint64
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return intrinsic_cr3();
        }

        /// <!-- description -->
        ///   @brief Sets the value of CR3
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set CR3 to
        ///
        static constexpr void
        set_cr3(bsl::safe_uint64 const &val) noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val "    // --
                             << bsl::hex(val)     // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return;
            }

            intrinsic_set_cr3(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of tp (TLS pointer)
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of tp (TLS pointer)
        ///
        [[nodiscard]] static constexpr auto
        tp() noexcept -> bsl::safe_uint64
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return intrinsic_tp();
        }

        /// <!-- description -->
        ///   @brief Sets the value of tp (TLS pointer)
        ///
        /// <!-- inputs/outputs -->
        ///   @param val the value to set tp (TLS pointer) to
        ///
        static constexpr void
        set_tp(bsl::safe_uint64 const &val) noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val "    // --
                             << bsl::hex(val)     // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return;
            }

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
        tls_reg(bsl::safe_uint64 const &reg) noexcept -> bsl::safe_uint64
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            if (bsl::unlikely(!reg)) {
                bsl::error() << "invalid reg "    // --
                             << bsl::hex(reg)     // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return {};
            }

            return intrinsic_tls_reg(reg.get());
        }

        /// <!-- description -->
        ///   @brief Sets the value of a requested TLS register
        ///
        /// <!-- inputs/outputs -->
        ///   @param reg the TLS register to set
        ///   @param val the value to set the TLS register to
        ///
        static constexpr void
        set_tls_reg(bsl::safe_uint64 const &reg, bsl::safe_uint64 const &val) noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            if (bsl::unlikely(!reg)) {
                bsl::error() << "invalid reg "    // --
                             << bsl::hex(reg)     // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val "    // --
                             << bsl::hex(val)     // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return;
            }

            intrinsic_set_tls_reg(reg.get(), val.get());
        }

        /// <!-- description -->
        ///   @brief Halts the CPU
        ///
        static constexpr void
        halt() noexcept
        {
            if (bsl::is_constant_evaluated()) {
                return;
            }

            intrinsic_halt();
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr the MSR to read from
        ///   @return Returns the value of requested MSR
        ///
        [[nodiscard]] static constexpr auto
        rdmsr(bsl::safe_uint32 const &msr) noexcept -> bsl::safe_uint64
        {
            bsl::exit_code ret{};
            bsl::safe_uint64 val{};

            if (bsl::is_constant_evaluated()) {
                return {};
            }

            if (bsl::unlikely(!msr)) {
                bsl::error() << "invalid msr "    // --
                             << bsl::hex(msr)     // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return bsl::safe_uint64::failure();
            }

            ret = intrinsic_rdmsr(msr.get(), val.data());
            if (bsl::unlikely(ret != bsl::exit_success)) {
                bsl::error() << "rdmsr failed for msr "    // --
                             << bsl::hex(msr)              // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::safe_uint64::failure();
            }

            return val;
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
        wrmsr(bsl::safe_uint32 const &msr, bsl::safe_uint64 const &val) noexcept -> bsl::errc_type
        {
            bsl::exit_code ret{};

            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!msr)) {
                bsl::error() << "invalid msr "    // --
                             << bsl::hex(msr)     // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val "    // --
                             << bsl::hex(val)     // --
                             << bsl::endl         // --
                             << bsl::here();      // --

                return bsl::errc_failure;
            }

            ret = intrinsic_wrmsr(msr.get(), val.get());
            if (bsl::unlikely(ret != bsl::exit_success)) {
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
        ///   @brief Invalidates the TLB mapping for a given virtual page and
        ///     a given ASID
        ///
        /// <!-- inputs/outputs -->
        ///   @param addr The address to invalidate
        ///   @param asid The ASID to invalidate
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        invlpga(bsl::safe_uint64 const &addr, bsl::safe_uint64 const &asid) noexcept
            -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!addr)) {
                bsl::error() << "invalid addr "    // --
                             << bsl::hex(addr)     // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!asid)) {
                bsl::error() << "invalid asid "    // --
                             << bsl::hex(asid)     // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            intrinsic_invlpga(addr.get(), asid.get());
            return bsl::errc_success;
        }
    };
}

#endif
