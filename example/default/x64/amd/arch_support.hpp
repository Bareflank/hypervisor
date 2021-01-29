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
        constexpr bsl::safe_uintmax EXIT_REASON_CPUID{bsl::to_umax(0x72U)};

        /// NOTE:
        /// - At a minimum, we need to handle CPUID on AMD. Note that the
        ///   "run" APIs all return an error code, but for the most part we
        ///   can ignore them. If the this function succeeds, it will not
        ///   return. If it fails, it will return, and the error code is
        ///   always UNKNOWN. We output the current line so that debugging
        ///   the issue is easier.
        ///

        switch (exit_reason.get()) {
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
        /// - Set up ASID
        ///

        constexpr bsl::safe_uint64 guest_asid_idx{bsl::to_u64(0x0058)};
        constexpr bsl::safe_uint32 guest_asid_val{bsl::to_u32(0x1)};

        status = syscall::bf_vps_op_write32(handle, vpsid, guest_asid_idx, guest_asid_val);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        /// NOTE:
        /// - Set up wht intercept controls. On AMD, we need to intercept
        ///   VMRun, and CPUID if we plan to support reporting and stopping.
        ///

        constexpr bsl::safe_uint64 intercept_instruction1_idx{bsl::to_u64(0x000CU)};
        constexpr bsl::safe_uint32 intercept_instruction1_val{bsl::to_u32(0x00040000U)};
        constexpr bsl::safe_uint64 intercept_instruction2_idx{bsl::to_u64(0x0010U)};
        constexpr bsl::safe_uint32 intercept_instruction2_val{bsl::to_u32(0x00000001U)};

        status = syscall::bf_vps_op_write32(
            handle, vpsid, intercept_instruction1_idx, intercept_instruction1_val);
        if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
            bsl::print<bsl::V>() << bsl::here();
            return bsl::errc_failure;
        }

        status = syscall::bf_vps_op_write32(
            handle, vpsid, intercept_instruction2_idx, intercept_instruction2_val);
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
