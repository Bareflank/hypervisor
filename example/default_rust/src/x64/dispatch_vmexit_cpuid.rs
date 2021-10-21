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

const CPUID_COMMAND_EAX: u32 = 0x400000FF;
const CPUID_COMMAND_ECX_STOP: u32 = 0xBF000000;
const CPUID_COMMAND_ECX_REPORT_ON: u32 = 0xBF000001;
const CPUID_COMMAND_ECX_REPORT_OFF: u32 = 0xBF000002;

const CPUID_COMMAND_RAX_SUCCESS: u32 = 0x0;
const CPUID_COMMAND_RAX_FAILURE: u32 = 0x1;

/// <!-- description -->
///   @brief Handles the CPUID VMexit
///
/// <!-- inputs/outputs -->
///   @param gs the gs_t to use
///   @param tls the tls_t to use
///   @param sys the bf_syscall_t to use
///   @param intrinsic the intrinsic_t to use
///   @param vsid the ID of the VS that generated the VMExit
///   @return Returns bsl::errc_success on success, bsl::errc_failure
///     and friends otherwise
///
pub fn dispatch_vmexit_cpuid(
    gs: &crate::GsT,
    tls: &crate::TlsT,
    sys: &mut syscall::BfSyscallT,
    intrinsic: &crate::IntrinsicT,
    vsid: bsl::SafeU16,
) -> bsl::ErrcType {
    let mut rax = syscall::BfSyscallT::bf_tls_rax();
    let mut rcx = syscall::BfSyscallT::bf_tls_rcx();

    bsl::discard(gs);
    bsl::discard(tls);

    // NOTE:
    // - Before we execute CPUID, we need to check to see if we have
    //   received a CPUID command. If we have, we need to handle this
    //   CPUID differently. These are defined in the loader.
    //

    if bsl::to_u32_unsafe(rax) == CPUID_COMMAND_EAX {
        match bsl::to_u32_unsafe(rcx).get() {
            CPUID_COMMAND_ECX_STOP => {
                // NOTE:
                // - If this is the first PP to stop (which is the
                //   last PP in the list as we stop in reverse order),
                //   print out how much memory was used by the
                //   hypervisor. This is optional of course.
                //

                let last_online_ppid =
                    (syscall::BfSyscallT::bf_tls_online_pps() - bsl::SafeU16::magic_1()).checked();
                if syscall::BfSyscallT::bf_tls_ppid() == last_online_ppid {
                    print!("\n");
                    syscall::bf_debug_op_dump_page_pool();
                    print!("\n");
                } else {
                    bsl::touch();
                }

                // NOTE:
                // - The following is another optional debug feature that
                //   will show a log of the most recent VMExits that have
                //   occurred.
                //

                if bsl::debug_level_is_at_least_vv() {
                    print!("\n");
                    syscall::bf_debug_op_dump_vmexit_log(syscall::BfSyscallT::bf_tls_ppid());
                }

                // NOTE:
                // - Report that the root OS is no longer in a VM for
                //   this specific PP. Note that you can do whatever
                //   you want here, this is just the default behavior.
                //   To report success on promotion after promotion
                //   takes place would require that the loader reports
                //   success, which we do not do as we are not sure
                //   what the extension wants, so the message here
                //   should state that we are "about to", and not that
                //   it is "done", because it might fail.
                //

                debug!(
                    "about to {}promote{} root OS on pp {}{:#06x}{}\n",
                    bsl::red,
                    bsl::rst,
                    bsl::cyn,
                    syscall::BfSyscallT::bf_tls_ppid(),
                    bsl::rst
                );

                // NOTE:
                // - The promote ABI will load the microkernel by
                //   replacing the CPU's state withthe VP state
                //   associated with the provided VSID. If all
                //   goes well, bf_vs_op_promote will not return,
                //   and the system will continue executing with the
                //   hypervisor turned off.
                //

                syscall::BfSyscallT::bf_tls_set_rax(bsl::to_u64(CPUID_COMMAND_RAX_SUCCESS));
                return sys.bf_vs_op_promote(vsid);
            }

            CPUID_COMMAND_ECX_REPORT_ON => {
                // NOTE:
                // - Report that the root OS is now in a VM for this
                //   specific PP.
                //

                debug!(
                    "root OS had been {}demoted{} to vm {}{:#06x}{} on pp {}{:#06x}{}\n",
                    bsl::red,
                    bsl::rst,
                    bsl::cyn,
                    syscall::BfSyscallT::bf_tls_vmid(),
                    bsl::rst,
                    bsl::cyn,
                    syscall::BfSyscallT::bf_tls_ppid(),
                    bsl::rst
                );

                syscall::BfSyscallT::bf_tls_set_rax(bsl::to_u64(CPUID_COMMAND_RAX_SUCCESS));
                return sys.bf_vs_op_advance_ip_and_run_current();
            }

            CPUID_COMMAND_ECX_REPORT_OFF => {
                // NOTE:
                // - There is nothing to do here as we report off
                //   right before promotion takes place.
                //

                syscall::BfSyscallT::bf_tls_set_rax(bsl::to_u64(CPUID_COMMAND_RAX_SUCCESS));
                return sys.bf_vs_op_advance_ip_and_run_current();
            }

            _ => {
                error!("unsupported cpuid command {:#018x}\n{}", rcx, bsl::here());
            }
        }

        syscall::BfSyscallT::bf_tls_set_rax(bsl::to_u64(CPUID_COMMAND_RAX_FAILURE));
        return sys.bf_vs_op_advance_ip_and_run_current();
    }

    let mut rbx = syscall::BfSyscallT::bf_tls_rbx();
    let mut rdx = syscall::BfSyscallT::bf_tls_rdx();
    intrinsic.cpuid(&mut rax, &mut rbx, &mut rcx, &mut rdx);

    syscall::BfSyscallT::bf_tls_set_rax(rax);
    syscall::BfSyscallT::bf_tls_set_rbx(rbx);
    syscall::BfSyscallT::bf_tls_set_rcx(rcx);
    syscall::BfSyscallT::bf_tls_set_rdx(rdx);
    return sys.bf_vs_op_advance_ip_and_run_current();
}
