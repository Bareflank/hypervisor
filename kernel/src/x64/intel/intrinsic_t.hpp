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
#include <invept_descriptor_t.hpp>
#include <invvpid_descriptor_t.hpp>
#include <tlb_flush_type_t.hpp>

#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

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
    ///   @brief Implements intrinsic_t::invept
    ///
    /// <!-- inputs/outputs -->
    ///   @param desc n/a
    ///   @param type n/a
    ///
    extern "C" void intrinsic_invept(void const *const desc, bsl::uint64 const type) noexcept;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::invvpid
    ///
    /// <!-- inputs/outputs -->
    ///   @param desc n/a
    ///   @param type n/a
    ///
    extern "C" void intrinsic_invvpid(void const *const desc, bsl::uint64 const type) noexcept;

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
    ///   @brief Implements intrinsic_t::cr4
    ///
    /// <!-- inputs/outputs -->
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto intrinsic_cr4() noexcept -> bsl::uint64;

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
    ///   @brief Implements intrinsic_t::vmld
    ///
    /// <!-- inputs/outputs -->
    ///   @param phys n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto intrinsic_vmld(void const *const phys) noexcept -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::vmcl
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_phys n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto intrinsic_vmcl(void const *const pmut_phys) noexcept
        -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::vmrd16
    ///
    /// <!-- inputs/outputs -->
    ///   @param field n/a
    ///   @param pmut_val n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    intrinsic_vmrd16(bsl::uint64 const field, bsl::uint16 *const pmut_val) noexcept
        -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::vmrd32
    ///
    /// <!-- inputs/outputs -->
    ///   @param field n/a
    ///   @param pmut_val n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    intrinsic_vmrd32(bsl::uint64 const field, bsl::uint32 *const pmut_val) noexcept
        -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::vmrd64
    ///
    /// <!-- inputs/outputs -->
    ///   @param field n/a
    ///   @param pmut_val n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    intrinsic_vmrd64(bsl::uint64 const field, bsl::uint64 *const pmut_val) noexcept
        -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::vmwr16
    ///
    /// <!-- inputs/outputs -->
    ///   @param field n/a
    ///   @param val n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    intrinsic_vmwr16(bsl::uint64 const field, bsl::uint16 const val) noexcept -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::vmwr32
    ///
    /// <!-- inputs/outputs -->
    ///   @param field n/a
    ///   @param val n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    intrinsic_vmwr32(bsl::uint64 const field, bsl::uint32 const val) noexcept -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::vmwr64
    ///
    /// <!-- inputs/outputs -->
    ///   @param field n/a
    ///   @param val n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    intrinsic_vmwr64(bsl::uint64 const field, bsl::uint64 const val) noexcept -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Implements intrinsic_t::vmwrfunc
    ///
    /// <!-- inputs/outputs -->
    ///   @param field n/a
    ///   @param pmut_func n/a
    ///   @return n/a
    ///
    extern "C" [[nodiscard]] auto
    intrinsic_vmwrfunc(bsl::uint64 const field, void (*const pmut_func)() noexcept) noexcept
        -> bsl::errc_type;

    /// <!-- description -->
    ///   @brief Executes the VMLaunch/VMResume instructions. When this
    ///     function returns, a "VMExit" has occurred and must be handled.
    ///
    /// <!-- inputs/outputs -->
    ///   @param pmut_vmcs_missing_registers a pointer to struct for where to
    ///     store the registers not saved in the VMCS
    ///   @return Returns the exit reason associated with the VMExit
    ///
    extern "C" [[nodiscard]] auto intrinsic_vmrun(void *const pmut_vmcs_missing_registers) noexcept
        -> bsl::uintmx;

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
        ///     the given VMID as a VPID (remember that Intel calls the tag
        ///      VPID, and that is not the same thing as a Bareflank VPID as
        ///      an Intel VPID really is the VMID as VMCS VPIDs need to be the
        ///      same for all VPs in a VM for things to make sense from a
        ///      cache point of view).
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
            /// - See the documentation on IPI for how to implement a broadcast
            ///   TLB flush on Intel. MicroV/mono already has the code for
            ///   this. Basically, when the intrinsics class is implemented,
            ///   it will need a bool array for each PP. Before this code is
            ///   executed, it should set all of the bits in the array. Then
            ///   it would execute a broadcast INIT to all of the CPUs. The
            ///   INIT will always trap on Intel, but the microkernel should
            ///   check to see if a TLB flush is active by asking the intrinsic
            ///   class if the bit in the array is set. If it is, it will not
            ///   send the INIT to the extension, but instead will call this
            ///   function with broadcast set to false. This will always clear
            ///   the bit and perform a local TLB flush. The PP that made the
            ///   broadcast call will simply spin, checking to see if any of the
            ///   bits in the array are set. Once all of the bits are clear, it
            ///   can return.
            /// - Obviously, setting all of the bits in the array will have to
            ///   be mutex locked. Otherwise, two cores could try to flush the
            ///   TLB at the same time. A local flush should NOT take the
            ///   mutex. If a race occurs, its fine because the flush will have
            ///   happened.
            /// - Might also need to store the enum that tells this function
            ///   what kind of local flush should occur. When the microkernel
            ///   gets the INIT, the function that returns the status can
            ///   actually return this enum, so that it knows that local flush
            ///   to call.
            /// - If no flush is in progress, the extension should get the
            ///   INIT.
            /// - The biggest problem with all of this is that sending an INIT
            ///   requires you to communicate with the APIC. My advice is
            ///   we should only ever support the x2APIC. Meaning, MicroV on
            ///   Intel should only ever start if the x2APIC is enabled. This
            ///   way, we do not have to worry about the memory mapped version
            ///   which is not easy to deal with. Then, all you have to do is
            ///   call a write MSR to send the broadcast INIT.
            ///

            switch (type) {
                case tlb_flush_type_t::local: {
                    if (syscall::BF_INVALID_ID == vmid) {
                        intrinsic_invlpg(addr.get());
                    }
                    else {
                        invvpid_descriptor_t const desc{vmid.get(), {}, {}, {}, addr.get()};
                        intrinsic_invvpid(&desc, {});
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
        ///   @brief Returns the value of ES
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the value of ES
        ///
        [[nodiscard]] static constexpr auto
        es_selector() noexcept -> bsl::safe_u16
        {
            return bsl::to_u16(intrinsic_es_selector());
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
            return bsl::to_u16(intrinsic_cs_selector());
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
            return bsl::to_u16(intrinsic_ss_selector());
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
            return bsl::to_u16(intrinsic_ds_selector());
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
            return bsl::to_u16(intrinsic_fs_selector());
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
            return bsl::to_u16(intrinsic_gs_selector());
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
            return bsl::to_u16(intrinsic_tr_selector());
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
            return bsl::to_u64(intrinsic_cr0());
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
            return bsl::to_u64(intrinsic_cr3());
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
            return bsl::to_u64(intrinsic_cr4());
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
            bsl::expects(val.is_valid_and_checked());
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
            bsl::expects(val.is_valid_and_checked());
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
            bsl::expects(reg.is_valid_and_checked());
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
            bsl::expects(reg.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

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
            bsl::expects(msr.is_valid_and_checked());

            bsl::safe_u64 mut_val{};
            auto const ret{intrinsic_rdmsr(msr.get(), mut_val.data())};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "rdmsr failed for msr "    // --
                             << bsl::hex(msr)              // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return bsl::safe_u64::failure();
            }

            bsl::ensures(mut_val.is_valid_and_checked());
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
            bsl::expects(msr.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            auto const ret{intrinsic_wrmsr(msr.get(), val.get())};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "wrmsr failed for msr "    // --
                             << bsl::hex(msr)              // --
                             << " with value "             // --
                             << bsl::hex(val)              // --
                             << bsl::endl                  // --
                             << bsl::here();               // --

                return ret;
            }

            return ret;
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
        vmld(void const *const phys) noexcept -> bsl::errc_type
        {
            bsl::expects(nullptr != phys);

            auto const ret{intrinsic_vmld(phys)};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmld failed for "     // --
                             << phys                   // --
                             << " with error code "    // --
                             << ret                    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return ret;
            }

            return ret;
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
            bsl::expects(nullptr != phys);

            auto const ret{intrinsic_vmcl(phys)};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmcl failed for "     // --
                             << phys                   // --
                             << " with error code "    // --
                             << ret                    // --
                             << bsl::endl              // --
                             << bsl::here();           // --

                return bsl::errc_failure;
            }

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
        [[nodiscard]] static constexpr auto
        vmrd16(bsl::safe_u64 const &field, bsl::uint16 *const pmut_val) noexcept -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());
            bsl::expects(nullptr != pmut_val);

            auto const ret{intrinsic_vmrd16(field.get(), pmut_val)};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmrd failed for field "    // --
                             << bsl::hex(field)             // --
                             << " with error code "         // --
                             << ret                         // --
                             << bsl::endl                   // --
                             << bsl::here();                // --

                return bsl::errc_failure;
            }

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
        [[nodiscard]] static constexpr auto
        vmrd16(bsl::safe_u64 const &field) noexcept -> bsl::safe_u16
        {
            bsl::expects(field.is_valid_and_checked());

            bsl::safe_u16 mut_val{};
            auto const ret{intrinsic_vmrd16(field.get(), mut_val.data())};
            if (bsl::unlikely(!ret)) {
                return bsl::safe_u16::failure();
            }

            bsl::ensures(mut_val.is_valid_and_checked());
            return mut_val;
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
        [[nodiscard]] static constexpr auto
        vmrd32(bsl::safe_u64 const &field, bsl::uint32 *const pmut_val) noexcept -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());
            bsl::expects(nullptr != pmut_val);

            auto const ret{intrinsic_vmrd32(field.get(), pmut_val)};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmrd failed for field "    // --
                             << bsl::hex(field)             // --
                             << " with error code "         // --
                             << ret                         // --
                             << bsl::endl                   // --
                             << bsl::here();                // --

                return bsl::errc_failure;
            }

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
        [[nodiscard]] static constexpr auto
        vmrd32(bsl::safe_u64 const &field) noexcept -> bsl::safe_u32
        {
            bsl::expects(field.is_valid_and_checked());

            bsl::safe_u32 mut_val{};
            auto const ret{intrinsic_vmrd32(field.get(), mut_val.data())};
            if (bsl::unlikely(!ret)) {
                return bsl::safe_u32::failure();
            }

            bsl::ensures(mut_val.is_valid_and_checked());
            return mut_val;
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
        [[nodiscard]] static constexpr auto
        vmrd64(bsl::safe_u64 const &field, bsl::uint64 *const pmut_val) noexcept -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());
            bsl::expects(nullptr != pmut_val);

            auto const ret{intrinsic_vmrd64(field.get(), pmut_val)};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmrd failed for field "    // --
                             << bsl::hex(field)             // --
                             << " with error code "         // --
                             << ret                         // --
                             << bsl::endl                   // --
                             << bsl::here();                // --

                return bsl::errc_failure;
            }

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
        [[nodiscard]] static constexpr auto
        vmrd64(bsl::safe_u64 const &field) noexcept -> bsl::safe_u64
        {
            bsl::expects(field.is_valid_and_checked());

            bsl::safe_u64 mut_val{};
            auto const ret{intrinsic_vmrd64(field.get(), mut_val.data())};
            if (bsl::unlikely(!ret)) {
                return bsl::safe_u64::failure();
            }

            bsl::ensures(mut_val.is_valid_and_checked());
            return mut_val;
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
        [[nodiscard]] static constexpr auto
        vmwr16(bsl::safe_u64 const &field, bsl::safe_u16 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            auto const ret{intrinsic_vmwr16(field.get(), val.get())};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmwr failed for field "    // --
                             << bsl::hex(field)             // --
                             << " with value "              // --
                             << bsl::hex(val)               // --
                             << " with error code "         // --
                             << ret                         // --
                             << bsl::endl                   // --
                             << bsl::here();                // --

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
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmwr32(bsl::safe_u64 const &field, bsl::safe_u32 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            auto const ret{intrinsic_vmwr32(field.get(), val.get())};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmwr failed for field "    // --
                             << bsl::hex(field)             // --
                             << " with value "              // --
                             << bsl::hex(val)               // --
                             << " with error code "         // --
                             << ret                         // --
                             << bsl::endl                   // --
                             << bsl::here();                // --

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
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        vmwr64(bsl::safe_u64 const &field, bsl::safe_u64 const &val) noexcept -> bsl::errc_type
        {
            bsl::expects(field.is_valid_and_checked());
            bsl::expects(val.is_valid_and_checked());

            auto const ret{intrinsic_vmwr64(field.get(), val.get())};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmwr failed for field "    // --
                             << bsl::hex(field)             // --
                             << " with value "              // --
                             << bsl::hex(val)               // --
                             << " with error code "         // --
                             << ret                         // --
                             << bsl::endl                   // --
                             << bsl::here();                // --

                return bsl::errc_failure;
            }

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
            bsl::expects(nullptr != pmut_func);

            auto const ret{intrinsic_vmwrfunc(field.get(), pmut_func)};
            if (bsl::unlikely(!ret)) {
                bsl::error() << "vmwr failed for field "    // --
                             << bsl::hex(field)             // --
                             << " with error code "         // --
                             << ret                         // --
                             << bsl::endl                   // --
                             << bsl::here();                // --

                return bsl::errc_failure;
            }

            return bsl::errc_success;
        }
    };
}

#endif
