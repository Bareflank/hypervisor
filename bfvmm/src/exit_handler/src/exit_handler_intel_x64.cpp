//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <debug.h>
#include <view_as_pointer.h>
#include <exit_handler/exit_handler_intel_x64.h>
#include <exit_handler/exit_handler_intel_x64_entry.h>
#include <exit_handler/exit_handler_intel_x64_support.h>

#include <mutex>
std::mutex g_unimplemented_handler_mutex;

exit_handler_intel_x64::exit_handler_intel_x64(std::shared_ptr<intrinsics_intel_x64> intrinsics) :
    m_intrinsics(std::move(intrinsics)),
    m_exit_reason(0),
    m_exit_qualification(0),
    m_exit_instruction_length(0),
    m_exit_instruction_information(0)
{
    if (!m_intrinsics)
        m_intrinsics = std::make_shared<intrinsics_intel_x64>();
}

void
exit_handler_intel_x64::dispatch()
{
    m_exit_reason =
        vmread(VMCS_EXIT_REASON);
    m_exit_qualification =
        vmread(VMCS_EXIT_QUALIFICATION);
    m_exit_instruction_length =
        vmread(VMCS_VM_EXIT_INSTRUCTION_LENGTH);
    m_exit_instruction_information =
        vmread(VMCS_VM_EXIT_INSTRUCTION_INFORMATION);

    switch (m_exit_reason & 0x0000FFFF)
    {
        case VM_EXIT_REASON_EXCEPTION_OR_NON_MASKABLE_INTERRUPT:
            handle_exception_or_non_maskable_interrupt();
            break;

        case VM_EXIT_REASON_EXTERNAL_INTERRUPT:
            handle_external_interrupt();
            break;

        case VM_EXIT_REASON_TRIPLE_FAULT:
            handle_triple_fault();
            break;

        case VM_EXIT_REASON_INIT_SIGNAL:
            handle_init_signal();
            break;

        case VM_EXIT_REASON_SIPI:
            handle_sipi();
            break;

        case VM_EXIT_REASON_SMI:
            handle_smi();
            break;

        case VM_EXIT_REASON_OTHER_SMI:
            handle_other_smi();
            break;

        case VM_EXIT_REASON_INTERRUPT_WINDOW:
            handle_interrupt_window();
            break;

        case VM_EXIT_REASON_NMI_WINDOW:
            handle_nmi_window();
            break;

        case VM_EXIT_REASON_TASK_SWITCH:
            handle_task_switch();
            break;

        case VM_EXIT_REASON_CPUID:
            handle_cpuid();
            break;

        case VM_EXIT_REASON_GETSEC:
            handle_getsec();
            break;

        case VM_EXIT_REASON_HLT:
            handle_hlt();
            break;

        case VM_EXIT_REASON_INVD:
            handle_invd();
            break;

        case VM_EXIT_REASON_INVLPG:
            handle_invlpg();
            break;

        case VM_EXIT_REASON_RDPMC:
            handle_rdpmc();
            break;

        case VM_EXIT_REASON_RDTSC:
            handle_rdtsc();
            break;

        case VM_EXIT_REASON_RSM:
            handle_rsm();
            break;

        case VM_EXIT_REASON_VMCALL:
            handle_vmcall();
            break;

        case VM_EXIT_REASON_VMCLEAR:
            handle_vmclear();
            break;

        case VM_EXIT_REASON_VMLAUNCH:
            handle_vmlaunch();
            break;

        case VM_EXIT_REASON_VMPTRLD:
            handle_vmptrld();
            break;

        case VM_EXIT_REASON_VMPTRST:
            handle_vmptrst();
            break;

        case VM_EXIT_REASON_VMREAD:
            handle_vmread();
            break;

        case VM_EXIT_REASON_VMRESUME:
            handle_vmresume();
            break;

        case VM_EXIT_REASON_VMWRITE:
            handle_vmwrite();
            break;

        case VM_EXIT_REASON_VMXOFF:
            handle_vmxoff();
            break;

        case VM_EXIT_REASON_VMXON:
            handle_vmxon();
            break;

        case VM_EXIT_REASON_CONTROL_REGISTER_ACCESSES:
            handle_control_register_accesses();
            break;

        case VM_EXIT_REASON_MOV_DR:
            handle_mov_dr();
            break;

        case VM_EXIT_REASON_IO_INSTRUCTION:
            handle_io_instruction();
            break;

        case VM_EXIT_REASON_RDMSR:
            handle_rdmsr();
            break;

        case VM_EXIT_REASON_WRMSR:
            handle_wrmsr();
            break;

        case VM_EXIT_REASON_VM_ENTRY_FAILURE_INVALID_GUEST_STATE:
            handle_vm_entry_failure_invalid_guest_state();
            break;

        case VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOADING:
            handle_vm_entry_failure_msr_loading();
            break;

        case VM_EXIT_REASON_MWAIT:
            handle_mwait();
            break;

        case VM_EXIT_REASON_MONITOR_TRAP_FLAG:
            handle_monitor_trap_flag();
            break;

        case VM_EXIT_REASON_MONITOR:
            handle_monitor();
            break;

        case VM_EXIT_REASON_PAUSE:
            handle_pause();
            break;

        case VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT:
            handle_vm_entry_failure_machine_check_event();
            break;

        case VM_EXIT_REASON_TPR_BELOW_THRESHOLD:
            handle_tpr_below_threshold();
            break;

        case VM_EXIT_REASON_APIC_ACCESS:
            handle_apic_access();
            break;

        case VM_EXIT_REASON_VIRTUALIZED_EOI:
            handle_virtualized_eoi();
            break;

        case VM_EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR:
            handle_access_to_gdtr_or_idtr();
            break;

        case VM_EXIT_REASON_ACCESS_TO_LDTR_OR_TR:
            handle_access_to_ldtr_or_tr();
            break;

        case VM_EXIT_REASON_EPT_VIOLATION:
            handle_ept_violation();
            break;

        case VM_EXIT_REASON_EPT_MISCONFIGURATION:
            handle_ept_misconfiguration();
            break;

        case VM_EXIT_REASON_INVEPT:
            handle_invept();
            break;

        case VM_EXIT_REASON_RDTSCP:
            handle_rdtscp();
            break;

        case VM_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
            handle_vmx_preemption_timer_expired();
            break;

        case VM_EXIT_REASON_INVVPID:
            handle_invvpid();
            break;

        case VM_EXIT_REASON_WBINVD:
            handle_wbinvd();
            break;

        case VM_EXIT_REASON_XSETBV:
            handle_xsetbv();
            break;

        case VM_EXIT_REASON_APIC_WRITE:
            handle_apic_write();
            break;

        case VM_EXIT_REASON_RDRAND:
            handle_rdrand();
            break;

        case VM_EXIT_REASON_INVPCID:
            handle_invpcid();
            break;

        case VM_EXIT_REASON_VMFUNC:
            handle_vmfunc();
            break;

        case VM_EXIT_REASON_RDSEED:
            handle_rdseed();
            break;

        case VM_EXIT_REASON_XSAVES:
            handle_xsaves();
            break;

        case VM_EXIT_REASON_XRSTORS:
            handle_xrstors();
            break;

        default:
            unimplemented_handler();
            break;
    };

    m_vmcs->resume();
}

void
exit_handler_intel_x64::halt() noexcept
{
    std::lock_guard<std::mutex> guard(g_unimplemented_handler_mutex);

    bferror << bfendl;
    bferror << bfendl;
    bferror << "Guest register state: " << bfendl;
    bferror << "----------------------------------------------------" << bfendl;
    bferror << "- m_state_save->rax: " << view_as_pointer(m_state_save->rax) << bfendl;
    bferror << "- m_state_save->rbx: " << view_as_pointer(m_state_save->rbx) << bfendl;
    bferror << "- m_state_save->rcx: " << view_as_pointer(m_state_save->rcx) << bfendl;
    bferror << "- m_state_save->rdx: " << view_as_pointer(m_state_save->rdx) << bfendl;
    bferror << "- m_state_save->rbp: " << view_as_pointer(m_state_save->rbp) << bfendl;
    bferror << "- m_state_save->rsi: " << view_as_pointer(m_state_save->rsi) << bfendl;
    bferror << "- m_state_save->rdi: " << view_as_pointer(m_state_save->rdi) << bfendl;
    bferror << "- m_state_save->r08: " << view_as_pointer(m_state_save->r08) << bfendl;
    bferror << "- m_state_save->r09: " << view_as_pointer(m_state_save->r09) << bfendl;
    bferror << "- m_state_save->r10: " << view_as_pointer(m_state_save->r10) << bfendl;
    bferror << "- m_state_save->r11: " << view_as_pointer(m_state_save->r11) << bfendl;
    bferror << "- m_state_save->r12: " << view_as_pointer(m_state_save->r12) << bfendl;
    bferror << "- m_state_save->r13: " << view_as_pointer(m_state_save->r13) << bfendl;
    bferror << "- m_state_save->r14: " << view_as_pointer(m_state_save->r14) << bfendl;
    bferror << "- m_state_save->r15: " << view_as_pointer(m_state_save->r15) << bfendl;
    bferror << "- m_state_save->rip: " << view_as_pointer(m_state_save->rip) << bfendl;
    bferror << "- m_state_save->rsp: " << view_as_pointer(m_state_save->rsp) << bfendl;

    bferror << bfendl;
    bferror << bfendl;
    bferror << "CPU Halted: " << bfendl;
    bferror << "----------------------------------------------------" << bfendl;
    bferror << "- vcpuid: " << m_state_save->vcpuid << bfendl;

    bferror << bfendl;
    bferror << bfendl;

    g_unimplemented_handler_mutex.unlock();

    m_intrinsics->stop();
}

void
exit_handler_intel_x64::handle_exception_or_non_maskable_interrupt()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_external_interrupt()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_triple_fault()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_init_signal()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_sipi()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_smi()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_other_smi()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_interrupt_window()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_nmi_window()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_task_switch()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_cpuid()
{
    m_intrinsics->cpuid(&m_state_save->rax,
                        &m_state_save->rbx,
                        &m_state_save->rcx,
                        &m_state_save->rdx);

    advance_rip();
}

void
exit_handler_intel_x64::handle_getsec()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_hlt()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_invd()
{
    m_intrinsics->wbinvd();
    advance_rip();
}

void
exit_handler_intel_x64::handle_invlpg()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_rdpmc()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_rdtsc()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_rsm()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmcall()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmclear()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmlaunch()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmptrld()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmptrst()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmread()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmresume()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmwrite()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmxoff()
{
    m_vmcs->promote();
}

void
exit_handler_intel_x64::handle_vmxon()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_control_register_accesses()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_mov_dr()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_io_instruction()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_rdmsr()
{
    uint64_t msr = 0;

    switch (m_state_save->rcx)
    {
        case IA32_DEBUGCTL_MSR:
            msr = vmread(VMCS_GUEST_IA32_DEBUGCTL_FULL);
            break;
        case IA32_PAT_MSR:
            msr = vmread(VMCS_GUEST_IA32_PAT_FULL);
            break;
        case IA32_EFER_MSR:
            msr = vmread(VMCS_GUEST_IA32_EFER_FULL);
            break;
        case IA32_PERF_GLOBAL_CTRL_MSR:
            msr = vmread(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL);
            break;
        case IA32_SYSENTER_CS_MSR:
            msr = vmread(VMCS_GUEST_IA32_SYSENTER_CS);
            break;
        case IA32_SYSENTER_ESP_MSR:
            msr = vmread(VMCS_GUEST_IA32_SYSENTER_ESP);
            break;
        case IA32_SYSENTER_EIP_MSR:
            msr = vmread(VMCS_GUEST_IA32_SYSENTER_EIP);
            break;
        case IA32_FS_BASE_MSR:
            msr = vmread(VMCS_GUEST_FS_BASE);
            break;
        case IA32_GS_BASE_MSR:
            msr = vmread(VMCS_GUEST_GS_BASE);
            break;
        default:
            msr = m_intrinsics->read_msr(static_cast<uint32_t>(m_state_save->rcx));
            break;

        // QUIRK:
        //
        // The following is specifically for CPU-Z. For whatever reason, it is
        // reading the following undefined MSRs, which causes the system to
        // freeze since attempting to read these MSRs in the exit handler
        // will cause a GP which is not being caught. The result is, the core
        // that runs RDMSR on these freezes, the the other cores receive an
        // INIT signal to reset, and the system dies.
        //

        case 0x31:
        case 0x39:
        case 0x1ae:
        case 0x1af:
        case 0x602:
            msr = 0;
            break;
    }

    m_state_save->rax = ((msr >> 0x00) & 0x00000000FFFFFFFF);
    m_state_save->rdx = ((msr >> 0x20) & 0x00000000FFFFFFFF);

    advance_rip();
}

void
exit_handler_intel_x64::handle_wrmsr()
{
    uint64_t msr = 0;

    msr |= ((m_state_save->rax & 0x00000000FFFFFFFF) << 0x00);
    msr |= ((m_state_save->rdx & 0x00000000FFFFFFFF) << 0x20);

    switch (m_state_save->rcx)
    {
        case IA32_DEBUGCTL_MSR:
            vmwrite(VMCS_GUEST_IA32_DEBUGCTL_FULL, msr);
            break;
        case IA32_PAT_MSR:
            vmwrite(VMCS_GUEST_IA32_PAT_FULL, msr);
            break;
        case IA32_EFER_MSR:
            vmwrite(VMCS_GUEST_IA32_EFER_FULL, msr);
            break;
        case IA32_PERF_GLOBAL_CTRL_MSR:
            vmwrite(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL, msr);
            break;
        case IA32_SYSENTER_CS_MSR:
            vmwrite(VMCS_GUEST_IA32_SYSENTER_CS, msr);
            break;
        case IA32_SYSENTER_ESP_MSR:
            vmwrite(VMCS_GUEST_IA32_SYSENTER_ESP, msr);
            break;
        case IA32_SYSENTER_EIP_MSR:
            vmwrite(VMCS_GUEST_IA32_SYSENTER_EIP, msr);
            break;
        case IA32_FS_BASE_MSR:
            vmwrite(VMCS_GUEST_FS_BASE, msr);
            break;
        case IA32_GS_BASE_MSR:
            vmwrite(VMCS_GUEST_GS_BASE, msr);
            break;
        default:
            m_intrinsics->write_msr(static_cast<uint32_t>(m_state_save->rcx), msr);
            break;
    }

    advance_rip();
}

void
exit_handler_intel_x64::handle_vm_entry_failure_invalid_guest_state()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vm_entry_failure_msr_loading()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_mwait()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_monitor_trap_flag()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_monitor()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_pause()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vm_entry_failure_machine_check_event()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_tpr_below_threshold()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_apic_access()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_virtualized_eoi()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_access_to_gdtr_or_idtr()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_access_to_ldtr_or_tr()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_ept_violation()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_ept_misconfiguration()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_invept()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_rdtscp()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmx_preemption_timer_expired()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_invvpid()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_wbinvd()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_xsetbv()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_apic_write()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_rdrand()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_invpcid()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_vmfunc()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_rdseed()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_xsaves()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::handle_xrstors()
{ unimplemented_handler(); }

void
exit_handler_intel_x64::advance_rip()
{
    m_state_save->rip += m_exit_instruction_length;
}

void
exit_handler_intel_x64::unimplemented_handler()
{
    std::lock_guard<std::mutex> guard(g_unimplemented_handler_mutex);

    bferror << bfendl;
    bferror << bfendl;
    bferror << "Unimplemented Exit Handler: " << bfendl;
    bferror << "----------------------------------------------------" << bfendl;
    bferror << "- exit reason: "
            << view_as_pointer(m_exit_reason) << bfendl;
    bferror << "- exit reason string: "
            << exit_reason_to_str(m_exit_reason & 0x0000FFFF) << bfendl;
    bferror << "- exit qualification: "
            << view_as_pointer(m_exit_qualification) << bfendl;
    bferror << "- instruction length: "
            << view_as_pointer(m_exit_instruction_length) << bfendl;
    bferror << "- instruction information: "
            << view_as_pointer(m_exit_instruction_information) << bfendl;

    if ((m_exit_reason & 0x80000000) != 0)
    {
        bferror << bfendl;
        bferror << "VM-entry failure detected!!!" << bfendl;
        bferror << bfendl;

        m_vmcs->check_vmcs_control_state();
        m_vmcs->check_vmcs_guest_state();
        m_vmcs->check_vmcs_host_state();
    }

    g_unimplemented_handler_mutex.unlock();

    this->halt();
}

const char *
exit_handler_intel_x64::exit_reason_to_str(uint64_t exit_reason)
{
    switch (exit_reason)
    {
        case VM_EXIT_REASON_EXCEPTION_OR_NON_MASKABLE_INTERRUPT:
            return "VM_EXIT_REASON_EXCEPTION_OR_NON_MASKABLE_INTERRUPT";

        case VM_EXIT_REASON_EXTERNAL_INTERRUPT:
            return "VM_EXIT_REASON_EXTERNAL_INTERRUPT";

        case VM_EXIT_REASON_TRIPLE_FAULT:
            return "VM_EXIT_REASON_TRIPLE_FAULT";

        case VM_EXIT_REASON_INIT_SIGNAL:
            return "VM_EXIT_REASON_INIT_SIGNAL";

        case VM_EXIT_REASON_SIPI:
            return "VM_EXIT_REASON_SIPI";

        case VM_EXIT_REASON_SMI:
            return "VM_EXIT_REASON_SMI";

        case VM_EXIT_REASON_OTHER_SMI:
            return "VM_EXIT_REASON_OTHER_SMI";

        case VM_EXIT_REASON_INTERRUPT_WINDOW:
            return "VM_EXIT_REASON_INTERRUPT_WINDOW";

        case VM_EXIT_REASON_NMI_WINDOW:
            return "VM_EXIT_REASON_NMI_WINDOW";

        case VM_EXIT_REASON_TASK_SWITCH:
            return "VM_EXIT_REASON_TASK_SWITCH";

        case VM_EXIT_REASON_CPUID:
            return "VM_EXIT_REASON_CPUID";

        case VM_EXIT_REASON_GETSEC:
            return "VM_EXIT_REASON_GETSEC";

        case VM_EXIT_REASON_HLT:
            return "VM_EXIT_REASON_HLT";

        case VM_EXIT_REASON_INVD:
            return "VM_EXIT_REASON_INVD";

        case VM_EXIT_REASON_INVLPG:
            return "VM_EXIT_REASON_INVLPG";

        case VM_EXIT_REASON_RDPMC:
            return "VM_EXIT_REASON_RDPMC";

        case VM_EXIT_REASON_RDTSC:
            return "VM_EXIT_REASON_RDTSC";

        case VM_EXIT_REASON_RSM:
            return "VM_EXIT_REASON_RSM";

        case VM_EXIT_REASON_VMCALL:
            return "VM_EXIT_REASON_VMCALL";

        case VM_EXIT_REASON_VMCLEAR:
            return "VM_EXIT_REASON_VMCLEAR";

        case VM_EXIT_REASON_VMLAUNCH:
            return "VM_EXIT_REASON_VMLAUNCH";

        case VM_EXIT_REASON_VMPTRLD:
            return "VM_EXIT_REASON_VMPTRLD";

        case VM_EXIT_REASON_VMPTRST:
            return "VM_EXIT_REASON_VMPTRST";

        case VM_EXIT_REASON_VMREAD:
            return "VM_EXIT_REASON_VMREAD";

        case VM_EXIT_REASON_VMRESUME:
            return "VM_EXIT_REASON_VMRESUME";

        case VM_EXIT_REASON_VMWRITE:
            return "VM_EXIT_REASON_VMWRITE";

        case VM_EXIT_REASON_VMXOFF:
            return "VM_EXIT_REASON_VMXOFF";

        case VM_EXIT_REASON_VMXON:
            return "VM_EXIT_REASON_VMXON";

        case VM_EXIT_REASON_CONTROL_REGISTER_ACCESSES:
            return "VM_EXIT_REASON_CONTROL_REGISTER_ACCESSES";

        case VM_EXIT_REASON_MOV_DR:
            return "VM_EXIT_REASON_MOV_DR";

        case VM_EXIT_REASON_IO_INSTRUCTION:
            return "VM_EXIT_REASON_IO_INSTRUCTION";

        case VM_EXIT_REASON_RDMSR:
            return "VM_EXIT_REASON_RDMSR";

        case VM_EXIT_REASON_WRMSR:
            return "VM_EXIT_REASON_WRMSR";

        case VM_EXIT_REASON_VM_ENTRY_FAILURE_INVALID_GUEST_STATE:
            return "VM_EXIT_REASON_VM_ENTRY_FAILURE_INVALID_GUEST_STATE";

        case VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOADING:
            return "VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOADING";

        case VM_EXIT_REASON_MWAIT:
            return "VM_EXIT_REASON_MWAIT";

        case VM_EXIT_REASON_MONITOR_TRAP_FLAG:
            return "VM_EXIT_REASON_MONITOR_TRAP_FLAG";

        case VM_EXIT_REASON_MONITOR:
            return "VM_EXIT_REASON_MONITOR";

        case VM_EXIT_REASON_PAUSE:
            return "VM_EXIT_REASON_PAUSE";

        case VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT:
            return "VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK_EVENT";

        case VM_EXIT_REASON_TPR_BELOW_THRESHOLD:
            return "VM_EXIT_REASON_TPR_BELOW_THRESHOLD";

        case VM_EXIT_REASON_APIC_ACCESS:
            return "VM_EXIT_REASON_APIC_ACCESS";

        case VM_EXIT_REASON_VIRTUALIZED_EOI:
            return "VM_EXIT_REASON_VIRTUALIZED_EOI";

        case VM_EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR:
            return "VM_EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR";

        case VM_EXIT_REASON_ACCESS_TO_LDTR_OR_TR:
            return "VM_EXIT_REASON_ACCESS_TO_LDTR_OR_TR";

        case VM_EXIT_REASON_EPT_VIOLATION:
            return "VM_EXIT_REASON_EPT_VIOLATION";

        case VM_EXIT_REASON_EPT_MISCONFIGURATION:
            return "VM_EXIT_REASON_EPT_MISCONFIGURATION";

        case VM_EXIT_REASON_INVEPT:
            return "VM_EXIT_REASON_INVEPT";

        case VM_EXIT_REASON_RDTSCP:
            return "VM_EXIT_REASON_RDTSCP";

        case VM_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
            return "VM_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED";

        case VM_EXIT_REASON_INVVPID:
            return "VM_EXIT_REASON_INVVPID";

        case VM_EXIT_REASON_WBINVD:
            return "VM_EXIT_REASON_WBINVD";

        case VM_EXIT_REASON_XSETBV:
            return "VM_EXIT_REASON_XSETBV";

        case VM_EXIT_REASON_APIC_WRITE:
            return "VM_EXIT_REASON_APIC_WRITE";

        case VM_EXIT_REASON_RDRAND:
            return "VM_EXIT_REASON_RDRAND";

        case VM_EXIT_REASON_INVPCID:
            return "VM_EXIT_REASON_INVPCID";

        case VM_EXIT_REASON_VMFUNC:
            return "VM_EXIT_REASON_VMFUNC";

        case VM_EXIT_REASON_RDSEED:
            return "VM_EXIT_REASON_RDSEED";

        case VM_EXIT_REASON_XSAVES:
            return "VM_EXIT_REASON_XSAVES";

        case VM_EXIT_REASON_XRSTORS:
            return "VM_EXIT_REASON_XRSTORS";

        default:
            return "UNKNOWN";
    };
}

uint64_t
exit_handler_intel_x64::vmread(uint64_t field) const
{
    uint64_t value = 0;

    if (!m_intrinsics->vmread(field, &value))
    {
        bferror << "exit_handler_intel_x64::vmread failed:" << bfendl;
        bferror << "    - field: " << view_as_pointer(field) << bfendl;

        throw std::runtime_error("vmread failed");
    }

    return value;
}

void
exit_handler_intel_x64::vmwrite(uint64_t field, uint64_t value)
{
    if (!m_intrinsics->vmwrite(field, value))
    {
        bferror << "exit_handler_intel_x64::vmwrite failed:" << bfendl;
        bferror << "    - field: " << view_as_pointer(field) << bfendl;
        bferror << "    - value: " << view_as_pointer(value) << bfendl;

        throw std::runtime_error("vmwrite failed");
    }
}
