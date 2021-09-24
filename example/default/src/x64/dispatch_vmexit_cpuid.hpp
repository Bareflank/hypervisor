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

#ifndef DISPATCH_VMEXIT_CPUID_HPP
#define DISPATCH_VMEXIT_CPUID_HPP

#include <bf_debug_ops.hpp>
#include <bf_syscall_t.hpp>
#include <cpuid_commands.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>

#include <bsl/convert.hpp>
#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/touch.hpp>

namespace example
{
    /// <!-- description -->
    ///   @brief Handles the CPUID VMexit
    ///
    /// <!-- inputs/outputs -->
    ///   @param gs the gs_t to use
    ///   @param tls the tls_t to use
    ///   @param mut_sys the bf_syscall_t to use
    ///   @param intrinsic the intrinsic_t to use
    ///   @param vsid the ID of the VS that generated the VMExit
    ///   @return Returns bsl::errc_success on success, bsl::errc_failure
    ///     and friends otherwise
    ///
    [[nodiscard]] static constexpr auto
    dispatch_vmexit_cpuid(
        gs_t const &gs,
        tls_t const &tls,
        syscall::bf_syscall_t &mut_sys,
        intrinsic_t const &intrinsic,
        bsl::safe_u16 const &vsid) noexcept -> bsl::errc_type
    {
        auto mut_rax{mut_sys.bf_tls_rax()};
        auto mut_rcx{mut_sys.bf_tls_rcx()};

        /// NOTE:
        /// - Before we execute CPUID, we need to check to see if we have
        ///   received a CPUID command. If we have, we need to handle this
        ///   CPUID differently. These are defined in the loader.
        ///

        if (loader::CPUID_COMMAND_EAX == bsl::to_u32_unsafe(mut_rax)) {
            switch (bsl::to_u32_unsafe(mut_rcx).get()) {
                case loader::CPUID_COMMAND_ECX_STOP.get(): {

                    /// NOTE:
                    /// - If this is the first PP to stop (which is the
                    ///   last PP in the list as we stop in reverse order),
                    ///   print out how much memory was used by the
                    ///   hypervisor. This is optional of course.
                    ///

                    auto const last_online_ppid{(mut_sys.bf_tls_online_pps() - 1_u16).checked()};
                    if (mut_sys.bf_tls_ppid() == last_online_ppid) {
                        bsl::print() << bsl::endl;
                        syscall::bf_debug_op_dump_page_pool();
                        bsl::print() << bsl::endl;
                    }
                    else {
                        bsl::touch();
                    }

                    /// NOTE:
                    /// - The following is another optional debug feature that
                    ///   will show a log of the most recent VMExits that have
                    ///   occurred.
                    ///

                    if constexpr (bsl::debug_level_is_at_least_vv()) {
                        bsl::print() << bsl::endl;
                        syscall::bf_debug_op_dump_vmexit_log(mut_sys.bf_tls_ppid());
                    }

                    /// NOTE:
                    /// - Report that the root OS is no longer in a VM for
                    ///   this specific PP. Note that you can do whatever
                    ///   you want here, this is just the default behavior.
                    ///   To report success on promotion after promotion
                    ///   takes place would require that the loader reports
                    ///   success, which we do not do as we are not sure
                    ///   what the extension wants, so the message here
                    ///   should state that we are "about to", and not that
                    ///   it is "done", because it might fail.
                    ///

                    bsl::debug() << bsl::rst << "about to"                         // --
                                 << bsl::red << " promote "                        // --
                                 << bsl::rst << "root OS on pp "                   // --
                                 << bsl::cyn << bsl::hex(mut_sys.bf_tls_ppid())    // --
                                 << bsl::rst << bsl::endl;                         // --

                    /// NOTE:
                    /// - The promote ABI will load the microkernel by
                    ///   replacing the CPU's state withthe VP state
                    ///   associated with the provided VSID. If all
                    ///   goes well, bf_vs_op_promote will not return,
                    ///   and the system will continue executing with the
                    ///   hypervisor turned off.
                    ///

                    mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);
                    return mut_sys.bf_vs_op_promote(vsid);
                }

                case loader::CPUID_COMMAND_ECX_REPORT_ON.get(): {

                    /// NOTE:
                    /// - Report that the root OS is now in a VM for this
                    ///   specific PP.
                    ///

                    bsl::debug() << bsl::rst << "root OS had been"                 // --
                                 << bsl::grn << " demoted "                        // --
                                 << bsl::rst << "to vm "                           // --
                                 << bsl::cyn << bsl::hex(mut_sys.bf_tls_vmid())    // --
                                 << bsl::rst << " on pp "                          // --
                                 << bsl::cyn << bsl::hex(mut_sys.bf_tls_ppid())    // --
                                 << bsl::rst << bsl::endl;                         // --

                    mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);
                    return mut_sys.bf_vs_op_advance_ip_and_run_current();
                }

                case loader::CPUID_COMMAND_ECX_REPORT_OFF.get(): {

                    /// NOTE:
                    /// - There is nothing to do here as we report off
                    ///   right before promotion takes place.
                    ///

                    mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);
                    return mut_sys.bf_vs_op_advance_ip_and_run_current();
                }

                default: {
                    bsl::error() << "unsupported cpuid command "    // --
                                 << bsl::hex(mut_rcx)               // --
                                 << bsl::endl                       // --
                                 << bsl::here();                    // --

                    break;
                }
            }

            mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_FAILURE);
            return mut_sys.bf_vs_op_advance_ip_and_run_current();
        }

        auto mut_rbx{mut_sys.bf_tls_rbx()};
        auto mut_rdx{mut_sys.bf_tls_rdx()};
        intrinsic.cpuid(gs, tls, mut_rax, mut_rbx, mut_rcx, mut_rdx);

        mut_sys.bf_tls_set_rax(mut_rax);
        mut_sys.bf_tls_set_rbx(mut_rbx);
        mut_sys.bf_tls_set_rcx(mut_rcx);
        mut_sys.bf_tls_set_rdx(mut_rdx);
        return mut_sys.bf_vs_op_advance_ip_and_run_current();
    }
}

#endif
