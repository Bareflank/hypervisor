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

#ifndef COMMON_ARCH_SUPPORT_HPP
#define COMMON_ARCH_SUPPORT_HPP

#include <cpuid_commands.hpp>
#include <mk_interface.hpp>

#include <bsl/convert.hpp>
#include <bsl/cstdint.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>
#include <bsl/unlikely.hpp>

namespace example
{
    /// <!-- description -->
    ///   @brief Executes the CPUID instruction given the provided EAX and ECX
    ///     and returns the results
    ///
    /// <!-- inputs/outputs -->
    ///   @param rax the index used by CPUID, returns resulting rax
    ///   @param rbx returns resulting rbx
    ///   @param rcx the subindex used by CPUID, returns the resulting rcx
    ///   @param rdx returns resulting rdx
    ///
    extern "C" void intrinsic_cpuid(
        bsl::uint64 *const rax,
        bsl::uint64 *const rbx,
        bsl::uint64 *const rcx,
        bsl::uint64 *const rdx) noexcept;

    /// <!-- description -->
    ///   @brief Handle CPUID VMExits
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
    handle_vmexit_cpuid(HANDLE_CONCEPT &handle, bsl::safe_uint16 const &vpsid) noexcept
        -> bsl::errc_type
    {
        bsl::safe_uintmax rax{syscall::bf_tls_rax(handle)};
        bsl::safe_uintmax rbx{syscall::bf_tls_rbx(handle)};
        bsl::safe_uintmax rcx{syscall::bf_tls_rcx(handle)};
        bsl::safe_uintmax rdx{syscall::bf_tls_rdx(handle)};

        /// NOTE:
        /// - Before we execute CPUID, we need to check to see if we have
        ///   received a CPUID command. If we have, we need to handle this
        ///   CPUID differently.
        ///

        if (loader::CPUID_COMMAND_EAX == bsl::to_u32_unsafe(rax)) {
            switch (bsl::to_u32_unsafe(rcx).get()) {
                case loader::CPUID_COMMAND_ECX_STOP.get(): {

                    /// NOTE:
                    /// - To support stopping the hypervisor, we need to
                    ///   report success by setting RAX to 0, and advancing
                    ///   the IP (as CPUID should not be executed again).
                    /// - From there, we can run the promote API, which will
                    ///   take the current state associated with the provided
                    ///   VPS and promote it, effectively stopping the
                    ///   hypervisor.
                    ///

                    syscall::bf_tls_set_rax(handle, bsl::ZERO_UMAX);

                    auto const status{syscall::bf_vps_op_advance_ip(handle, vpsid)};
                    if (bsl::unlikely(status != syscall::BF_STATUS_SUCCESS)) {
                        bsl::print<bsl::V>() << bsl::here();
                        return bsl::errc_failure;
                    }

                    syscall::bf_vps_op_promote(handle, vpsid);
                    return bsl::errc_failure;
                }

                case loader::CPUID_COMMAND_ECX_REPORT_ON.get(): {
                    bsl::debug() << "host os is"        // --
                                 << bsl::bold_green     // --
                                 << " now "             // --
                                 << bsl::reset_color    // --
                                 << "in a vm\n";        // --

                    return bsl::errc_success;
                }

                case loader::CPUID_COMMAND_ECX_REPORT_OFF.get(): {
                    bsl::debug() << "host os is"        // --
                                 << bsl::bold_red       // --
                                 << " not "             // --
                                 << bsl::reset_color    // --
                                 << "in a vm\n";        // --

                    return bsl::errc_success;
                }

                default: {
                    break;
                }
            }
        }
        else {

            /// NOTE:
            /// - The call to bsl::touch is only needed if you plan to enforce
            ///   MC/DC testing. bsl::touch() does nothing (i.e., it is an
            ///   empty function), but it reserves a line in the source code
            ///   that coverage tools can use to ensure the else{} path was
            ///   taken during unit testing. Feel free to ignore this if you
            ///   have no plans to support MC/DC testing.
            ///

            bsl::touch();
        }

        /// NOTE:
        /// - If we go this far, this is a normal CPUID, which means we
        ///   simply need to emulate its execution by calling CPUID and
        ///   returning the results.
        ///

        intrinsic_cpuid(rax.data(), rbx.data(), rcx.data(), rdx.data());

        syscall::bf_tls_set_rax(handle, rax);
        syscall::bf_tls_set_rbx(handle, rbx);
        syscall::bf_tls_set_rcx(handle, rcx);
        syscall::bf_tls_set_rdx(handle, rdx);

        return bsl::errc_success;
    }
}

#endif
