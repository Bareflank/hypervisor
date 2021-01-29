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

#ifndef ARCH_SUPPORT_HPP
#define ARCH_SUPPORT_HPP

#include <common_arch_support.hpp>
#include <mk_interface.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// @brief stores the MSR bitmap used by this extension
    inline void const *g_msr_bitmaps{};
    /// @brief stores the physical address of the MSR bitmap
    inline bsl::safe_uintmax g_msr_bitmaps_phys{};

    /// <!-- description -->
    ///   @brief Handle NMIs. This is required by Intel.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam HANDLE_CONCEPT the type of handle to use
    ///   @param handle the handle to use
    ///   @param vpsid the ID of the VPS that caused the VMExit
    ///   @return Returns bsl::errc_success on success and bsl::errc_failure
    ///     on failure.
    ///
    template<typename HANDLE_CONCEPT>
    [[nodiscard]] constexpr auto
    handle_vmexit_nmi(HANDLE_CONCEPT &handle, bsl::safe_uint16 const &vpsid) noexcept
        -> bsl::errc_type
    {
        /// NOTE:
        /// - If we caught an NMI, we need to inject it into the VM. To do
        ///   this, all we do is enable the NMI window, which will tell us
        ///   when we can safely inject the NMI.
        /// - Note that the microkernel will do the same thing. If an NMI
        ///   fires while the hypevisor is running, it will enable the NMI
        ///   window, which the extension will see as a VMExit, and must
        ///   from there, inject the NMI into the appropriate VPS.
        ///

        constexpr bsl::safe_uintmax vmcs_procbased_ctls_idx{bsl::to_umax(0x4002U)};
        constexpr bsl::safe_uint32 vmcs_set_nmi_window_exiting{bsl::to_u32(0x400000U)};

        bsl::safe_uint32 val;
        syscall::bf_status_t status{};

        status = syscall::bf_vps_op_read32(handle, vpsid, vmcs_procbased_ctls_idx, val);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        val |= vmcs_set_nmi_window_exiting;

        status = syscall::bf_vps_op_write32(handle, vpsid, vmcs_procbased_ctls_idx, val);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Handle NMIs Windows
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam HANDLE_CONCEPT the type of handle to use
    ///   @param handle the handle to use
    ///   @param vpsid the ID of the VPS that caused the VMExit
    ///   @return Returns bsl::errc_success on success and bsl::errc_failure
    ///     on failure.
    ///
    template<typename HANDLE_CONCEPT>
    [[nodiscard]] constexpr auto
    handle_vmexit_nmi_window(HANDLE_CONCEPT &handle, bsl::safe_uint16 const &vpsid) noexcept
        -> bsl::errc_type
    {
        /// NOTE:
        /// - If we see this exit, it is because an NMI fired. There are two
        ///   situations where this could occur, either while the hypervisor
        ///   is running, or the VPS is running. In either case, we need to
        ///   clear the NMI window and inject the NMI into the appropriate
        ///   VPS so that it can be handled. Note that Intel requires that
        ///   we handle NMIs, and they actually happen a lot with Linux based
        ///   on what hardware you are using (e.g., a laptop).
        ///

        constexpr bsl::safe_uintmax vmcs_procbased_ctls_idx{bsl::to_umax(0x4002U)};
        constexpr bsl::safe_uint32 vmcs_clear_nmi_window_exiting{bsl::to_u32(0xFFBFFFFFU)};

        bsl::safe_uint32 val;
        syscall::bf_status_t status{};

        status = syscall::bf_vps_op_read32(handle, vpsid, vmcs_procbased_ctls_idx, val);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        val &= vmcs_clear_nmi_window_exiting;

        status = syscall::bf_vps_op_write32(handle, vpsid, vmcs_procbased_ctls_idx, val);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Inject an NMI. If the NMI window was enabled, it is because we
        ///   need to inject a NMI. Note that the NMI window can be enabled
        ///   both by this extension, as well as by the microkernel itself,
        ///   so we are required to implement it on Intel.
        ///

        constexpr bsl::safe_uintmax vmcs_entry_interrupt_info_idx{bsl::to_umax(0x4016U)};
        constexpr bsl::safe_uint32 vmcs_entry_interrupt_info_val{bsl::to_u32(0x80000202U)};

        status = syscall::bf_vps_op_write32(
            handle, vpsid, vmcs_entry_interrupt_info_idx, vmcs_entry_interrupt_info_val);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        return bsl::errc_success;
    }

    /// <!-- description -->
    ///   @brief Implements the architecture specific VMExit handler.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam HANDLE_CONCEPT the type of handle to use
    ///   @param handle the handle to use
    ///   @param vpsid the ID of the VPS that generated the VMExit
    ///   @param exit_reason the exit reason associated with the VMExit
    ///
    template<typename HANDLE_CONCEPT>
    constexpr void
    vmexit(
        HANDLE_CONCEPT &handle,
        bsl::safe_uint16 const &vpsid,
        bsl::safe_uint64 const &exit_reason) noexcept
    {
        bsl::errc_type ret{};
        constexpr bsl::safe_uintmax EXIT_REASON_NMI{bsl::to_umax(0x0)};
        constexpr bsl::safe_uintmax EXIT_REASON_NMI_WINDOW{bsl::to_umax(0x8)};
        constexpr bsl::safe_uintmax EXIT_REASON_CPUID{bsl::to_umax(0xA)};

        /// NOTE:
        /// - At a minimum, we need to handle CPUID and NMIs on Intel. Note
        ///   that the "run" APIs all return an error code, but for the most
        ///   part we can ignore them. If the this function succeeds, it will
        ///   not return. If it fails, it will return, and the error code is
        ///   always UNKNOWN. We output the current line so that debugging
        ///   the issue is easier.
        ///

        switch (exit_reason.get()) {
            case EXIT_REASON_NMI.get(): {
                ret = handle_vmexit_nmi(handle, vpsid);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return;
                }

                bsl::discard(syscall::bf_vps_op_run_current(handle));
                bsl::print<bsl::V>() << bsl::here();
                return;
            }

            case EXIT_REASON_NMI_WINDOW.get(): {
                ret = handle_vmexit_nmi_window(handle, vpsid);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return;
                }

                bsl::discard(syscall::bf_vps_op_run_current(handle));
                bsl::print<bsl::V>() << bsl::here();
                return;
            }

            case EXIT_REASON_CPUID.get(): {
                ret = handle_vmexit_cpuid(handle, vpsid);
                if (bsl::unlikely(!ret)) {
                    bsl::print<bsl::V>() << bsl::here();
                    return;
                }

                bsl::discard(syscall::bf_vps_op_advance_ip_and_run_current(handle));
                bsl::print<bsl::V>() << bsl::here();
                return;
            }

            default: {
                break;
            }
        }

        bsl::error() << "unknown exit_reason: "    // --
                     << bsl::hex(exit_reason)      // --
                     << bsl::endl                  // --
                     << bsl::here();               // --
    }

    /// <!-- description -->
    ///   @brief Initializes a VPS with architecture specific stuff.
    ///
    /// <!-- inputs/outputs -->
    ///   @tparam HANDLE_CONCEPT the type of handle to use
    ///   @param handle the handle to use
    ///   @param vpsid the VPS being intialized
    ///   @return Returns bsl::errc_success on success and bsl::errc_failure
    ///     on failure.
    ///
    template<typename HANDLE_CONCEPT>
    [[nodiscard]] constexpr auto
    init_vps(HANDLE_CONCEPT &handle, bsl::safe_uint16 const &vpsid) noexcept -> bsl::errc_type
    {
        syscall::bf_status_t status{};

        /// NOTE:
        /// - Set up VPID
        ///

        constexpr bsl::safe_uintmax vmcs_vpid_idx{bsl::to_umax(0x0000U)};
        constexpr bsl::safe_uint16 vmcs_vpid_val{bsl::to_u16(0x1)};

        status = syscall::bf_vps_op_write16(handle, vpsid, vmcs_vpid_idx, vmcs_vpid_val);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Set up the VMCS link pointer
        ///

        constexpr bsl::safe_uintmax vmcs_link_ptr_idx{bsl::to_umax(0x2800U)};
        constexpr bsl::safe_uintmax vmcs_link_ptr_val{bsl::to_umax(0xFFFFFFFFFFFFFFFFU)};

        status = syscall::bf_vps_op_write64(handle, vpsid, vmcs_link_ptr_idx, vmcs_link_ptr_val);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Set up the VMCS pin based, proc based, exit and entry controls
        /// - We turn on MSR bitmaps so that we do not trap on MSR reads and
        ///   writes. If you do not configure this, or you use the bitmap
        ///   to trap to specific MSR accesses, make sure you keep the VMCS
        ///   in sync with your MSR mods. Any MSR that is in the VMCS also
        ///   needs to be written to the VMCS, otherwise, VMEntry/VMExit will
        ///   replace any values you write.
        /// - We also turn on secondary controls so that we can turn on VPID,
        ///   and turn on instructions that the OS is relying on, like
        ///   RDTSCP. Failure to do this will cause the invalid opcodes to
        ///   occur.
        /// - The lambda below performs the MSR conversion of the CTLS
        ///   registers to determine the bits that must always be set to 1,
        ///   and the bits that must always be set to 0. This allows us to
        ///   turn on as much as possible, letting the MSRs decide what is
        ///   allowed and what is not.
        /// - Also note that we do not attempt to detect support for the
        ///   secondary controls. This is because the loader ensures that
        ///   this support is present as it is a minimum requirement for the
        ///   project.
        ///

        constexpr bsl::safe_uintmax vmcs_pinbased_ctls_idx{bsl::to_umax(0x4000U)};
        constexpr bsl::safe_uintmax vmcs_procbased_ctls_idx{bsl::to_umax(0x4002U)};
        constexpr bsl::safe_uintmax vmcs_exit_ctls_idx{bsl::to_umax(0x400CU)};
        constexpr bsl::safe_uintmax vmcs_entry_ctls_idx{bsl::to_umax(0x4012U)};
        constexpr bsl::safe_uintmax vmcs_procbased_ctls2_idx{bsl::to_umax(0x401EU)};

        constexpr bsl::safe_uint32 ia32_vmx_true_pinbased_ctls{bsl::to_u32(0x48DU)};
        constexpr bsl::safe_uint32 ia32_vmx_true_procbased_ctls{bsl::to_u32(0x48EU)};
        constexpr bsl::safe_uint32 ia32_vmx_true_exit_ctls{bsl::to_u32(0x48FU)};
        constexpr bsl::safe_uint32 ia32_vmx_true_entry_ctls{bsl::to_u32(0x490U)};
        constexpr bsl::safe_uint32 ia32_vmx_true_procbased_ctls2{bsl::to_u32(0x48BU)};

        bsl::safe_uintmax ctls{};

        auto mask = [](bsl::safe_uintmax const &val) noexcept -> bsl::safe_uint32 {
            constexpr bsl::safe_uintmax ctls_mask{bsl::to_umax(0x00000000FFFFFFFFU)};
            constexpr bsl::safe_uintmax ctls_shift{bsl::to_umax(32)};
            return bsl::to_u32_unsafe((val & ctls_mask) & (val >> ctls_shift));
        };

        /// NOTE:
        /// - Configure the pin based controls
        ///

        status = syscall::bf_intrinsic_op_read_msr(handle, ia32_vmx_true_pinbased_ctls, ctls);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        status = syscall::bf_vps_op_write32(handle, vpsid, vmcs_pinbased_ctls_idx, mask(ctls));
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Configure the proc based controls
        ///

        constexpr bsl::safe_uintmax enable_msr_bitmaps{bsl::to_umax(0x10000000U)};
        constexpr bsl::safe_uintmax enable_procbased_ctls2{bsl::to_umax(0x80000000U)};

        status = syscall::bf_intrinsic_op_read_msr(handle, ia32_vmx_true_procbased_ctls, ctls);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        ctls |= enable_msr_bitmaps;
        ctls |= enable_procbased_ctls2;

        status = syscall::bf_vps_op_write32(handle, vpsid, vmcs_procbased_ctls_idx, mask(ctls));
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Configure the exit controls
        ///

        status = syscall::bf_intrinsic_op_read_msr(handle, ia32_vmx_true_exit_ctls, ctls);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        status = syscall::bf_vps_op_write32(handle, vpsid, vmcs_exit_ctls_idx, mask(ctls));
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Configure the entry controls
        ///

        status = syscall::bf_intrinsic_op_read_msr(handle, ia32_vmx_true_entry_ctls, ctls);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        status = syscall::bf_vps_op_write32(handle, vpsid, vmcs_entry_ctls_idx, mask(ctls));
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Configure the secondary proc controls.
        ///

        constexpr bsl::safe_uintmax enable_vpid{bsl::to_umax(0x00000020U)};
        constexpr bsl::safe_uintmax enable_rdtscp{bsl::to_umax(0x00000008U)};
        constexpr bsl::safe_uintmax enable_invpcid{bsl::to_umax(0x00001000U)};
        constexpr bsl::safe_uintmax enable_xsave{bsl::to_umax(0x00100000U)};
        constexpr bsl::safe_uintmax enable_uwait{bsl::to_umax(0x04000000U)};

        status = syscall::bf_intrinsic_op_read_msr(handle, ia32_vmx_true_procbased_ctls2, ctls);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        ctls |= enable_vpid;
        ctls |= enable_rdtscp;
        ctls |= enable_invpcid;
        ctls |= enable_xsave;
        ctls |= enable_uwait;

        status = syscall::bf_vps_op_write32(handle, vpsid, vmcs_procbased_ctls2_idx, mask(ctls));
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Configure the MSR bitmaps. This ensures that we do not trap
        ///   on MSR reads and writes. Also note that in most applications,
        ///   you only need one of these, regardless of the total number of
        ///   CPUs you are running on.
        ///

        constexpr bsl::safe_uintmax vmcs_msr_bitmaps{bsl::to_umax(0x2004U)};

        if (nullptr == g_msr_bitmaps) {
            status = syscall::bf_mem_op_alloc_page(handle, g_msr_bitmaps, g_msr_bitmaps_phys);
            if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }
        }

        status = syscall::bf_vps_op_write64(handle, vpsid, vmcs_msr_bitmaps, g_msr_bitmaps_phys);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Report success. Specifically, when we return to the root OS,
        ///   setting RAX tells the loader that the hypervisor was successfully
        ///   set up.
        ///

        syscall::bf_tls_set_rax(handle, bsl::ZERO_UMAX);
        return bsl::errc_success;
    }
}

#endif
