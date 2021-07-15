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

#ifndef VMEXIT_T_HPP
#define VMEXIT_T_HPP

#include <bf_debug_ops.hpp>
#include <bf_syscall_t.hpp>
#include <cpuid_commands.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vp_pool_t.hpp>
#include <vps_pool_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely_assert.hpp>

namespace example
{
    /// @brief used to enable the NMI window exiting bit
    constexpr auto VMCS_SET_NMI_WINDOW_EXITING{0x400000_u64};
    /// @brief used to disable the NMI window exiting bit
    constexpr auto VMCS_CLEAR_NMI_WINDOW_EXITING{0xFFBFFFFF_u64};
    /// @brief used to inject an interrupt
    constexpr auto VMCS_ENTRY_INTERRUPT_INFO_VAL{0x80000202_u64};

    /// @brief define the NMI exit reason
    constexpr auto EXIT_REASON_NMI{0x0_u64};
    /// @brief define the NMI window exit reason
    constexpr auto EXIT_REASON_NMI_WINDOW{0x8_u64};
    /// @brief define the CPUID exit reason
    constexpr auto EXIT_REASON_CPUID{0xA_u64};

    /// @class example::vmexit_t
    ///
    /// <!-- description -->
    ///   @brief Defines the extension's VMExit handler
    ///
    class vmexit_t final
    {
    public:
        /// <!-- description -->
        ///   @brief Initializes this vmexit_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vps_pool the vps_pool_t to use
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        initialize(
            gs_t &mut_gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            vp_pool_t const &vp_pool,
            vps_pool_t const &vps_pool) noexcept -> bsl::errc_type
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(vp_pool);
            bsl::discard(vps_pool);

            mut_gs.msr_bitmap = mut_sys.bf_mem_op_alloc_page(mut_gs.msr_bitmap_phys);
            if (bsl::unlikely_assert(nullptr == mut_gs.msr_bitmap)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            /// NOTE:
            /// - Add initialization code here if needed. Otherwise, this
            ///   function can be removed if it is not needed.
            ///

            return bsl::errc_success;
        }

        /// <!-- description -->
        ///   @brief Release the vmexit_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param mut_gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vps_pool the vps_pool_t to use
        ///
        static constexpr void
        release(
            gs_t &mut_gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            vp_pool_t const &vp_pool,
            vps_pool_t const &vps_pool) noexcept
        {
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(vp_pool);
            bsl::discard(vps_pool);

            /// NOTE:
            /// - Release functions are usually only needed in the event of
            ///   an error, or during unit testing.
            ///

            auto const ret{mut_sys.bf_mem_op_free_page(mut_gs.msr_bitmap)};
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
            }
            else {
                bsl::touch();
            }

            mut_gs.msr_bitmap = {};
            mut_gs.msr_bitmap_phys = {};
        }

        /// <!-- description -->
        ///   @brief Handle NMIs. This is required by Intel.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vps_pool the vps_pool_t to use
        ///   @param vpsid the ID of the VPS that generated the VMExit
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        handle_nmi(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            vp_pool_t const &vp_pool,
            vps_pool_t const &vps_pool,
            bsl::safe_uint16 const &vpsid) noexcept -> bsl::errc_type
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(vp_pool);
            bsl::discard(vps_pool);

            /// NOTE:
            /// - If we caught an NMI, we need to inject it into the VM. To do
            ///   this, all we do is enable the NMI window, which will tell us
            ///   when we can safely inject the NMI.
            /// - Note that the microkernel will do the same thing. If an NMI
            ///   fires while the hypevisor is running, it will enable the NMI
            ///   window, which the extension will see as a VMExit, and must
            ///   from there, inject the NMI into the appropriate VPS.
            ///

            auto mut_val{mut_sys.bf_vps_op_read(
                vpsid, syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls)};
            if (bsl::unlikely_assert(!mut_val)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_val |= VMCS_SET_NMI_WINDOW_EXITING;

            auto const ret{mut_sys.bf_vps_op_write(
                vpsid, syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls, mut_val)};
            if (bsl::unlikely_assert(!ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return ret;
            }

            return mut_sys.bf_vps_op_run_current();
        }

        /// <!-- description -->
        ///   @brief Handle NMIs Windows
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vps_pool the vps_pool_t to use
        ///   @param vpsid the ID of the VPS that generated the VMExit
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        handle_nmi_window(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            vp_pool_t const &vp_pool,
            vps_pool_t const &vps_pool,
            bsl::safe_uint16 const &vpsid) noexcept -> bsl::errc_type
        {
            bsl::errc_type mut_ret{};

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(intrinsic);
            bsl::discard(vp_pool);
            bsl::discard(vps_pool);

            /// NOTE:
            /// - If we see this exit, it is because an NMI fired. There are two
            ///   situations where this could occur, either while the hypervisor
            ///   is running, or the VPS is running. In either case, we need to
            ///   clear the NMI window and inject the NMI into the appropriate
            ///   VPS so that it can be handled. Note that Intel requires that
            ///   we handle NMIs, and they actually happen a lot with Linux based
            ///   on what hardware you are using (e.g., a laptop).
            ///

            auto mut_val{mut_sys.bf_vps_op_read(
                vpsid, syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls)};
            if (bsl::unlikely_assert(!mut_val)) {
                bsl::print<bsl::V>() << bsl::here();
                return bsl::errc_failure;
            }

            mut_val &= VMCS_CLEAR_NMI_WINDOW_EXITING;

            mut_ret = mut_sys.bf_vps_op_write(
                vpsid, syscall::bf_reg_t::bf_reg_t_primary_proc_based_vm_execution_ctls, mut_val);
            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            /// NOTE:
            /// - Inject an NMI. If the NMI window was enabled, it is because we
            ///   need to inject a NMI. Note that the NMI window can be enabled
            ///   both by this extension, as well as by the microkernel itself,
            ///   so we are required to implement it on Intel.
            ///

            mut_ret = mut_sys.bf_vps_op_write(
                vpsid,
                syscall::bf_reg_t::bf_reg_t_vmentry_interrupt_information_field,
                VMCS_ENTRY_INTERRUPT_INFO_VAL);

            if (bsl::unlikely_assert(!mut_ret)) {
                bsl::print<bsl::V>() << bsl::here();
                return mut_ret;
            }

            return mut_sys.bf_vps_op_run_current();
        }

        /// <!-- description -->
        ///   @brief Handles the CPUID VMexit
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vps_pool the vps_pool_t to use
        ///   @param vpsid the ID of the VPS that generated the VMExit
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        handle_cpuid(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            vp_pool_t const &vp_pool,
            vps_pool_t const &vps_pool,
            bsl::safe_uint16 const &vpsid) noexcept -> bsl::errc_type
        {
            bsl::discard(vp_pool);
            bsl::discard(vps_pool);

            /// NOTE:
            /// - The first thing that we need to do is get the current values
            ///   of RAX, RBX, RCX and RDX. We use the full 64bit versions to
            ///   ensure that we leave the upper half of these values intact,
            ///   otherwise we would not be emulating the execution of CPUID
            ///   correctly.
            ///

            auto mut_rax{mut_sys.bf_tls_rax()};
            auto mut_rbx{mut_sys.bf_tls_rbx()};
            auto mut_rcx{mut_sys.bf_tls_rcx()};
            auto mut_rdx{mut_sys.bf_tls_rdx()};

            /// NOTE:
            /// - Before we execute CPUID, we need to check to see if we have
            ///   received a CPUID command. If we have, we need to handle this
            ///   CPUID differently.
            ///

            if (loader::CPUID_COMMAND_EAX == bsl::to_u32_unsafe(mut_rax)) {
                switch (bsl::to_u32_unsafe(mut_rcx).get()) {
                    case loader::CPUID_COMMAND_ECX_STOP.get(): {

                        /// NOTE:
                        /// - If this is the first PP to stop (which is the
                        ///   last PP in the list as we stop in reverse order),
                        ///   print out how much memory was used by the
                        ///   hypervisor. This is a debugging feature that can
                        ///   be disabled, but it helps to track if memory is
                        ///   being over used.
                        ///

                        if (mut_sys.bf_tls_ppid() == (mut_sys.bf_tls_online_pps() - 1_u16)) {
                            bsl::print() << bsl::endl;
                            syscall::bf_debug_op_dump_page_pool();
                            bsl::print() << bsl::endl;
                        }
                        else {
                            bsl::touch();
                        }

                        /// NOTE:
                        /// - If the debug level is set to something higher
                        ///   than bsl::V, we can print out a VMExit log. How
                        ///   many entries we print is configurable, and you
                        ///   can control which PP you want to output if you
                        ///   only care about a specific PP. Note that this log
                        ///   will show VMExits for the whole PP, meaning you
                        ///   will see the order in which different VM's are
                        ///   making VMExits. The VMExit log doesn't attempt
                        ///   to decode anything, so that is up to you.
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
                        /// - Report success
                        ///

                        mut_sys.bf_tls_set_rax(loader::CPUID_COMMAND_RAX_SUCCESS);

                        /// NOTE:
                        /// - Before we can stop, we need to advance RIP.
                        ///   Normally, all of the other commands will advance
                        ///   and return to the VM at the end of this switch
                        ///   statement, but in this case, promote will not
                        ///   exit before then so we need to advance now.
                        ///

                        auto const ret{mut_sys.bf_vps_op_advance_ip(vpsid)};
                        if (bsl::unlikely_assert(!ret)) {
                            bsl::print<bsl::V>() << bsl::here();
                            return ret;
                        }

                        /// NOTE:
                        /// - The promote ABI will load the microkernel by
                        ///   replacing the CPU's state withthe VP state
                        ///   associated with the provided VPSID. If all
                        ///   goes well, bf_vps_op_promote will not return,
                        ///   and the system will continue executing with the
                        ///   hypervisor turned off.
                        ///

                        return mut_sys.bf_vps_op_promote(vpsid);
                    }

                    case loader::CPUID_COMMAND_ECX_REPORT_ON.get(): {

                        /// NOTE:
                        /// - Report that the root OS is now in a VM for this
                        ///   specific PP. Note that you can do whatever you
                        ///   want here, this is just the default behavior.
                        ///

                        bsl::debug() << bsl::rst << "root OS had been"                 // --
                                     << bsl::grn << " demoted "                        // --
                                     << bsl::rst << "to vm "                           // --
                                     << bsl::cyn << bsl::hex(mut_sys.bf_tls_vmid())    // --
                                     << bsl::rst << " on pp "                          // --
                                     << bsl::cyn << bsl::hex(mut_sys.bf_tls_ppid())    // --
                                     << bsl::rst << bsl::endl;                         // --

                        break;
                    }

                    case loader::CPUID_COMMAND_ECX_REPORT_OFF.get(): {

                        /// NOTE:
                        /// - There is nothing to do here as we report off
                        ///   right before promotion takes place. Extensions
                        ///   can use this as a means to perform actions if
                        ///   needed right before the loader sends the stop
                        ///   command. Just note that this command does not
                        ///   report success/failure.
                        ///

                        break;
                    }

                    default: {
                        bsl::error() << "unsupported cpuid command "    // --
                                     << bsl::hex(mut_rcx)               // --
                                     << bsl::endl                       // --
                                     << bsl::here();                    // --

                        break;
                    }
                }

                /// NOTE:
                /// - Complete this command by advancing RIP and running
                ///   the currently loaded VM, VP and VPS.
                ///

                return mut_sys.bf_vps_op_advance_ip_and_run_current();
            }

            /// NOTE:
            /// - If we got this far, this is a normal CPUID, which means we
            ///   simply need to emulate its execution by calling CPUID and
            ///   returning the results.
            ///

            intrinsic.cpuid(gs, tls, mut_rax, mut_rbx, mut_rcx, mut_rdx);

            /// NOTE:
            /// - Write the results of CPUID to the VP's registers. Note that
            ///   the above CPUID intrinsic takes in the full 64bit registers
            ///   but only touches the lower half of each register, which makes
            ///   sure that we are emulating CPUID properly.
            ///

            mut_sys.bf_tls_set_rax(mut_rax);
            mut_sys.bf_tls_set_rbx(mut_rbx);
            mut_sys.bf_tls_set_rcx(mut_rcx);
            mut_sys.bf_tls_set_rdx(mut_rdx);

            /// NOTE:
            /// - Complete the emulation of CPUID by advancing RIP and running
            ///   the currently loaded VM, VP and VPS.
            ///

            return mut_sys.bf_vps_op_advance_ip_and_run_current();
        }

        /// <!-- description -->
        ///   @brief Dispatches the VMExit.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param mut_sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vp_pool the vp_pool_t to use
        ///   @param vps_pool the vps_pool_t to use
        ///   @param vpsid the ID of the VPS that generated the VMExit
        ///   @param exit_reason the exit reason associated with the VMExit
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] static constexpr auto
        dispatch(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t &mut_sys,
            intrinsic_t const &intrinsic,
            vp_pool_t const &vp_pool,
            vps_pool_t const &vps_pool,
            bsl::safe_uint16 const &vpsid,
            bsl::safe_uint64 const &exit_reason) noexcept -> bsl::errc_type
        {
            /// NOTE:
            /// - Dispatch and handle each VMExit.
            ///

            switch (exit_reason.get()) {
                case EXIT_REASON_NMI.get(): {
                    return handle_nmi(gs, tls, mut_sys, intrinsic, vp_pool, vps_pool, vpsid);
                }

                case EXIT_REASON_NMI_WINDOW.get(): {
                    return handle_nmi_window(gs, tls, mut_sys, intrinsic, vp_pool, vps_pool, vpsid);
                }

                case EXIT_REASON_CPUID.get(): {
                    return handle_cpuid(gs, tls, mut_sys, intrinsic, vp_pool, vps_pool, vpsid);
                }

                default: {
                    break;
                }
            }

            /// NOTE:
            /// - If we got this far, it means that we were given a VMExit
            ///   that we do not handle.
            ///

            bsl::error() << "unsupported vmexit "    // --
                         << bsl::hex(exit_reason)    // --
                         << bsl::endl                // --
                         << bsl::here();             // --

            return bsl::errc_failure;
        }
    };
}

#endif
