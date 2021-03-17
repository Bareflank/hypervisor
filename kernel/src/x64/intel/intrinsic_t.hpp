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
#include <bsl/unlikely.hpp>

namespace mk
{
    namespace details
    {
        /// <!-- description -->
        ///   @brief Implements intrinsic_t::invlpg
        ///
        /// <!-- inputs/outputs -->
        ///   @param val n/a
        ///
        extern "C" void intrinsic_invlpg(bsl::uint64 const val) noexcept;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::es_selector
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto intrinsic_es_selector() noexcept -> bsl::uint16;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::es_selector
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto intrinsic_cs_selector() noexcept -> bsl::uint16;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::es_selector
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto intrinsic_ss_selector() noexcept -> bsl::uint16;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::es_selector
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto intrinsic_ds_selector() noexcept -> bsl::uint16;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::es_selector
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto intrinsic_fs_selector() noexcept -> bsl::uint16;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::es_selector
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto intrinsic_gs_selector() noexcept -> bsl::uint16;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::tr_selector
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto intrinsic_tr_selector() noexcept -> bsl::uint16;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::cr0
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto intrinsic_cr0() noexcept -> bsl::uint64;

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
        ///   @brief Implements intrinsic_t::cr4
        ///
        /// <!-- inputs/outputs -->
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto intrinsic_cr4() noexcept -> bsl::uint64;

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
        extern "C" [[nodiscard]] auto intrinsic_tls_reg(bsl::uint64 const reg) noexcept
            -> bsl::uint64;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::set_tls_reg
        ///
        /// <!-- inputs/outputs -->
        ///   @param reg n/a
        ///   @param val n/a
        ///
        extern "C" void
        intrinsic_set_tls_reg(bsl::uint64 const reg, bsl::uint64 const val) noexcept;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::halt
        ///
        extern "C" void intrinsic_halt() noexcept;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::rdmsr
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr n/a
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto
        intrinsic_rdmsr(bsl::uint32 msr, bsl::uint64 *const val) noexcept -> bsl::exit_code;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::wrmsr
        ///
        /// <!-- inputs/outputs -->
        ///   @param msr n/a
        ///   @param val n/a
        ///
        extern "C" [[nodiscard]] auto
        intrinsic_wrmsr(bsl::uint32 msr, bsl::uint64 const val) noexcept -> bsl::exit_code;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::vmload
        ///
        /// <!-- inputs/outputs -->
        ///   @param phys n/a
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto intrinsic_vmload(void *const phys) noexcept -> bsl::uint64;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::vmread16
        ///
        /// <!-- inputs/outputs -->
        ///   @param field n/a
        ///   @param val n/a
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto
        intrinsic_vmread16(bsl::uint64 field, bsl::uint16 *const val) noexcept -> bsl::uint64;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::vmread32
        ///
        /// <!-- inputs/outputs -->
        ///   @param field n/a
        ///   @param val n/a
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto
        intrinsic_vmread32(bsl::uint64 field, bsl::uint32 *const val) noexcept -> bsl::uint64;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::vmread64
        ///
        /// <!-- inputs/outputs -->
        ///   @param field n/a
        ///   @param val n/a
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto
        intrinsic_vmread64(bsl::uint64 field, bsl::uint64 *const val) noexcept -> bsl::uint64;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::vmwrite16
        ///
        /// <!-- inputs/outputs -->
        ///   @param field n/a
        ///   @param val n/a
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto
        intrinsic_vmwrite16(bsl::uint64 field, bsl::uint16 const val) noexcept -> bsl::uint64;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::vmwrite32
        ///
        /// <!-- inputs/outputs -->
        ///   @param field n/a
        ///   @param val n/a
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto
        intrinsic_vmwrite32(bsl::uint64 field, bsl::uint32 const val) noexcept -> bsl::uint64;

        /// <!-- description -->
        ///   @brief Implements intrinsic_t::vmwrite64
        ///
        /// <!-- inputs/outputs -->
        ///   @param field n/a
        ///   @param val n/a
        ///   @return n/a
        ///
        extern "C" [[nodiscard]] auto
        intrinsic_vmwrite64(bsl::uint64 field, bsl::uint64 const val) noexcept -> bsl::uint64;

        /// <!-- description -->
        ///   @brief Executes the VMLaunch/VMResume instructions. When this
        ///     function returns, a "VMExit" has occurred and must be handled.
        ///
        /// <!-- inputs/outputs -->
        ///   @param vmcs_missing_registers a pointer to struct for where to
        ///     store the registers not saved in the VMCS
        ///   @return Returns the error code associated with the VMExit
        ///
        extern "C" [[nodiscard]] auto intrinsic_vmrun(void *const vmcs_missing_registers) noexcept
            -> bsl::uintmax;
    }

    /// @class mk::intrinsic
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
        ///   @brief Default constructor
        ///
        constexpr intrinsic_t() noexcept = default;

        /// <!-- description -->
        ///   @brief Destructor
        ///
        constexpr ~intrinsic_t() noexcept = default;

        /// <!-- description -->
        ///   @brief copy constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///
        constexpr intrinsic_t(intrinsic_t const &o) noexcept = delete;

        /// <!-- description -->
        ///   @brief move constructor
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///
        constexpr intrinsic_t(intrinsic_t &&o) noexcept = delete;

        /// <!-- description -->
        ///   @brief copy assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being copied
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(intrinsic_t const &o) &noexcept
            -> intrinsic_t & = delete;

        /// <!-- description -->
        ///   @brief move assignment
        ///
        /// <!-- inputs/outputs -->
        ///   @param o the object being moved
        ///   @return a reference to *this
        ///
        [[maybe_unused]] constexpr auto operator=(intrinsic_t &&o) &noexcept
            -> intrinsic_t & = delete;

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
                bsl::error() << "invalid val: "    // --
                             << bsl::hex(val)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return;
            }

            details::intrinsic_invlpg(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of ES
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of ES
        ///
        [[nodiscard]] static constexpr auto
        es_selector() noexcept -> bsl::safe_uint16
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return details::intrinsic_es_selector();
        }

        /// <!-- description -->
        ///   @brief Returns the value of CS
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of CS
        ///
        [[nodiscard]] static constexpr auto
        cs_selector() noexcept -> bsl::safe_uint16
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return details::intrinsic_cs_selector();
        }

        /// <!-- description -->
        ///   @brief Returns the value of SS
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of SS
        ///
        [[nodiscard]] static constexpr auto
        ss_selector() noexcept -> bsl::safe_uint16
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return details::intrinsic_ss_selector();
        }

        /// <!-- description -->
        ///   @brief Returns the value of DS
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of DS
        ///
        [[nodiscard]] static constexpr auto
        ds_selector() noexcept -> bsl::safe_uint16
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return details::intrinsic_ds_selector();
        }

        /// <!-- description -->
        ///   @brief Returns the value of FS
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of FS
        ///
        [[nodiscard]] static constexpr auto
        fs_selector() noexcept -> bsl::safe_uint16
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return details::intrinsic_fs_selector();
        }

        /// <!-- description -->
        ///   @brief Returns the value of GS
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of GS
        ///
        [[nodiscard]] static constexpr auto
        gs_selector() noexcept -> bsl::safe_uint16
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return details::intrinsic_gs_selector();
        }

        /// <!-- description -->
        ///   @brief Returns the value of TR
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of TR
        ///
        [[nodiscard]] static constexpr auto
        tr_selector() noexcept -> bsl::safe_uint16
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return details::intrinsic_tr_selector();
        }

        /// <!-- description -->
        ///   @brief Returns the value of CR0
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of CR0
        ///
        [[nodiscard]] static constexpr auto
        cr0() noexcept -> bsl::safe_uint64
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return details::intrinsic_cr0();
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

            return details::intrinsic_cr3();
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
                bsl::error() << "invalid val: "    // --
                             << bsl::hex(val)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return;
            }

            details::intrinsic_set_cr3(val.get());
        }

        /// <!-- description -->
        ///   @brief Returns the value of CR4
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of CR4
        ///
        [[nodiscard]] static constexpr auto
        cr4() noexcept -> bsl::safe_uint64
        {
            if (bsl::is_constant_evaluated()) {
                return {};
            }

            return details::intrinsic_cr4();
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

            return details::intrinsic_tp();
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
                bsl::error() << "invalid val: "    // --
                             << bsl::hex(val)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return;
            }

            details::intrinsic_set_tp(val.get());
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
                bsl::error() << "invalid reg: "    // --
                             << bsl::hex(reg)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return {};
            }

            return details::intrinsic_tls_reg(reg.get());
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
                bsl::error() << "invalid reg: "    // --
                             << bsl::hex(reg)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val: "    // --
                             << bsl::hex(val)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return;
            }

            details::intrinsic_set_tls_reg(reg.get(), val.get());
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

            details::intrinsic_halt();
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
                bsl::error() << "invalid msr: "    // --
                             << bsl::hex(msr)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::safe_uint64::zero(true);
            }

            ret = details::intrinsic_rdmsr(msr.get(), val.data());
            if (bsl::unlikely(ret != bsl::exit_success)) {
                bsl::error() << "rdmsr failed for msr "    // --
                             << bsl::hex(msr)              // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::safe_uint64::zero(true);
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
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        wrmsr(bsl::safe_uint32 const &msr, bsl::safe_uint64 const &val) noexcept -> bsl::errc_type
        {
            bsl::exit_code ret{};

            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!msr)) {
                bsl::error() << "invalid msr: "    // --
                             << bsl::hex(msr)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val: "    // --
                             << bsl::hex(val)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            ret = details::intrinsic_wrmsr(msr.get(), val.get());
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
        ///   @brief Loads a VMCS given a pointer to the physical address
        ///     of the VMCS.
        ///
        /// <!-- inputs/outputs -->
        ///   @param phys a pointer to the physical address of the VMCS to
        ///     load.
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmload(void *const phys) noexcept -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(nullptr == phys)) {
                bsl::error() << "invalid phys: "    // --
                             << phys                // --
                             << bsl::endl           // --
                             << bsl::here();        // --

                return bsl::errc_failure;
            }

            auto const ret{details::intrinsic_vmload(phys)};
            if (bsl::unlikely(ret != bsl::ZERO_UMAX)) {
                bsl::error() << "vmload failed for "    // --
                             << phys                    // --
                             << bsl::endl               // --
                             << bsl::here();            // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 16 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 16 bit VMCS field to read
        ///   @param val the value to store the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmread16(bsl::safe_uint64 const &field, bsl::uint16 *const val) noexcept -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!field)) {
                bsl::error() << "invalid field: "    // --
                             << bsl::hex(field)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(nullptr == val)) {
                bsl::error() << "invalid val: "    // --
                             << val                // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            auto const ret{details::intrinsic_vmread16(field.get(), val)};
            if (bsl::unlikely(ret != bsl::ZERO_UMAX)) {
                bsl::error() << "vmread failed for field "    // --
                             << bsl::hex(field)               // --
                             << bsl::endl                     // --
                             << bsl::here();                  // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 32 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 32 bit VMCS field to read
        ///   @param val the value to store the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmread32(bsl::safe_uint64 const &field, bsl::uint32 *const val) noexcept -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!field)) {
                bsl::error() << "invalid field: "    // --
                             << bsl::hex(field)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(nullptr == val)) {
                bsl::error() << "invalid val: "    // --
                             << val                // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            auto const ret{details::intrinsic_vmread32(field.get(), val)};
            if (bsl::unlikely(ret != bsl::ZERO_UMAX)) {
                bsl::error() << "vmread failed for field "    // --
                             << bsl::hex(field)               // --
                             << bsl::endl                     // --
                             << bsl::here();                  // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 64 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 64 bit VMCS field to read
        ///   @param val the value to store the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmread64(bsl::safe_uint64 const &field, bsl::uint64 *const val) noexcept -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!field)) {
                bsl::error() << "invalid field: "    // --
                             << bsl::hex(field)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(nullptr == val)) {
                bsl::error() << "invalid val: "    // --
                             << val                // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            auto const ret{details::intrinsic_vmread64(field.get(), val)};
            if (bsl::unlikely(ret != bsl::ZERO_UMAX)) {
                bsl::error() << "vmread failed for field "    // --
                             << bsl::hex(field)               // --
                             << bsl::endl                     // --
                             << bsl::here();                  // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 16 bit VMCS field,
        ///     without outputting an error message
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 16 bit VMCS field to read
        ///   @param val the value to store the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmread16_quiet(bsl::safe_uint64 const &field, bsl::uint16 *const val) noexcept
            -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!field)) {
                bsl::error() << "invalid field: "    // --
                             << bsl::hex(field)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(nullptr == val)) {
                bsl::error() << "invalid val: "    // --
                             << val                // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            auto const ret{details::intrinsic_vmread16(field.get(), val)};
            if (bsl::unlikely(ret != bsl::ZERO_UMAX)) {
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 32 bit VMCS field,
        ///     without outputting an error message
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 32 bit VMCS field to read
        ///   @param val the value to store the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmread32_quiet(bsl::safe_uint64 const &field, bsl::uint32 *const val) noexcept
            -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!field)) {
                bsl::error() << "invalid field: "    // --
                             << bsl::hex(field)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(nullptr == val)) {
                bsl::error() << "invalid val: "    // --
                             << val                // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            auto const ret{details::intrinsic_vmread32(field.get(), val)};
            if (bsl::unlikely(ret != bsl::ZERO_UMAX)) {
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Returns the value of requested 64 bit VMCS field,
        ///     without outputting an error message
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 64 bit VMCS field to read
        ///   @param val the value to store the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmread64_quiet(bsl::safe_uint64 const &field, bsl::uint64 *const val) noexcept
            -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!field)) {
                bsl::error() << "invalid field: "    // --
                             << bsl::hex(field)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(nullptr == val)) {
                bsl::error() << "invalid val: "    // --
                             << val                // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            auto const ret{details::intrinsic_vmread64(field.get(), val)};
            if (bsl::unlikely(ret != bsl::ZERO_UMAX)) {
                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the value of requested 16 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 16 bit VMCS field to write to
        ///   @param val the value to set the 16 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmwrite16(bsl::safe_uint64 const &field, bsl::safe_uint16 const &val) noexcept
            -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!field)) {
                bsl::error() << "invalid field: "    // --
                             << bsl::hex(field)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val: "    // --
                             << bsl::hex(val)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            auto const ret{details::intrinsic_vmwrite16(field.get(), val.get())};
            if (bsl::unlikely(ret != bsl::ZERO_UMAX)) {
                bsl::error() << "vmwrite failed for field "    // --
                             << bsl::hex(field)                // --
                             << " with value "                 // --
                             << bsl::hex(val)                  // --
                             << bsl::endl                      // --
                             << bsl::here();                   // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the value of requested 32 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 32 bit VMCS field to write to
        ///   @param val the value to set the 32 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmwrite32(bsl::safe_uint64 const &field, bsl::safe_uint32 const &val) noexcept
            -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!field)) {
                bsl::error() << "invalid field: "    // --
                             << bsl::hex(field)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val: "    // --
                             << bsl::hex(val)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            auto const ret{details::intrinsic_vmwrite32(field.get(), val.get())};
            if (bsl::unlikely(ret != bsl::ZERO_UMAX)) {
                bsl::error() << "vmwrite failed for field "    // --
                             << bsl::hex(field)                // --
                             << " with value "                 // --
                             << bsl::hex(val)                  // --
                             << bsl::endl                      // --
                             << bsl::here();                   // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Sets the value of requested 64 bit VMCS field
        ///
        /// <!-- inputs/outputs -->
        ///   @param field the 64 bit VMCS field to write to
        ///   @param val the value to set the 64 bit VMCS field to
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmwrite64(bsl::safe_uint64 const &field, bsl::safe_uint64 const &val) noexcept
            -> bsl::errc_type
        {
            if (bsl::is_constant_evaluated()) {
                return bsl::errc_success;
            }

            if (bsl::unlikely(!field)) {
                bsl::error() << "invalid field: "    // --
                             << bsl::hex(field)      // --
                             << bsl::endl            // --
                             << bsl::here();         // --

                return bsl::errc_failure;
            }

            if (bsl::unlikely(!val)) {
                bsl::error() << "invalid val: "    // --
                             << bsl::hex(val)      // --
                             << bsl::endl          // --
                             << bsl::here();       // --

                return bsl::errc_failure;
            }

            auto const ret{details::intrinsic_vmwrite64(field.get(), val.get())};
            if (bsl::unlikely(ret != bsl::ZERO_UMAX)) {
                bsl::error() << "vmwrite failed for field "    // --
                             << bsl::hex(field)                // --
                             << " with value "                 // --
                             << bsl::hex(val)                  // --
                             << bsl::endl                      // --
                             << bsl::here();                   // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }
    };
}

#endif
