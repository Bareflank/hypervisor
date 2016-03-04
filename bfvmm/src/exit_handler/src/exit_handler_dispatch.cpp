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

#include <iostream>
#include <exit_handler/exit_handler.h>
#include <exit_handler/exit_handler_dispatch.h>
#include <vcpu/vcpu_manager.h>

exit_handler_dispatch::exit_handler_dispatch(intrinsics_intel_x64 *intrinsics) : m_intrinsics(intrinsics)
{
}

exit_handler_dispatch::~exit_handler_dispatch()
{
}

void
exit_handler_dispatch::dispatch()
{
    m_intrinsics->vmread(VMCS_EXIT_REASON, &m_exit_reason);
    m_intrinsics->vmread(VMCS_EXIT_QUALIFICATION, &m_exit_qualification);
    m_intrinsics->vmread(VMCS_VM_EXIT_INSTRUCTION_LENGTH, &m_exit_instruction_length);
    m_intrinsics->vmread(VMCS_VM_EXIT_INSTRUCTION_INFORMATION, &m_exit_instruction_information);

    switch (m_exit_reason)
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
}

void
exit_handler_dispatch::handle_exception_or_non_maskable_interrupt()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_external_interrupt()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_triple_fault()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_init_signal()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_sipi()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_smi()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_other_smi()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_interrupt_window()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_nmi_window()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_task_switch()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_cpuid()
{
    guest_cpuid();
    advance_rip();
}

void
exit_handler_dispatch::handle_getsec()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_hlt()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_invd()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_invlpg()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_rdpmc()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_rdtsc()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_rsm()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmcall()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmclear()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmlaunch()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmptrld()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmptrst()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmread()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmresume()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmwrite()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmxoff()
{
    g_guest_rax = 0x00;
    g_vcm->promote_vcpu(0);
}

void
exit_handler_dispatch::handle_vmxon()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_control_register_accesses()
{
    auto control_register = ((m_exit_qualification & 0x0000000F) >> 0);
    auto access_type = ((m_exit_qualification & 0x00000030) >> 4);
    auto general_purpose_register = ((m_exit_qualification & 0x00000F00) >> 8);

    if (control_register != 3)
        goto unimplemented;

    if (access_type >= 2)
        goto unimplemented;

    if (access_type == 0)
    {
        switch (general_purpose_register)
        {
            case 0:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_rax);
                break;

            case 1:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_rcx);
                break;

            case 2:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_rdx);
                break;

            case 3:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_rbx);
                break;

            case 4:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_rsp);
                break;

            case 5:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_rbp);
                break;

            case 6:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_rsi);
                break;

            case 7:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_rdi);
                break;

            case 8:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_r08);
                break;

            case 9:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_r09);
                break;

            case 10:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_r10);
                break;

            case 11:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_r11);
                break;

            case 12:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_r12);
                break;

            case 13:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_r13);
                break;

            case 14:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_r14);
                break;

            case 15:
                m_intrinsics->vmwrite(VMCS_GUEST_CR3, g_guest_r15);
                break;

            default:
                goto unimplemented;
        }

        advance_rip();
        return;
    }

    if (access_type == 1)
    {
        switch (general_purpose_register)
        {
            case 0:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_rax);
                break;

            case 1:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_rcx);
                break;

            case 2:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_rdx);
                break;

            case 3:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_rbx);
                break;

            case 4:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_rsp);
                break;

            case 5:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_rbp);
                break;

            case 6:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_rsi);
                break;

            case 7:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_rdi);
                break;

            case 8:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_r08);
                break;

            case 9:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_r09);
                break;

            case 10:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_r10);
                break;

            case 11:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_r11);
                break;

            case 12:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_r12);
                break;

            case 13:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_r13);
                break;

            case 14:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_r14);
                break;

            case 15:
                m_intrinsics->vmread(VMCS_GUEST_CR3, &g_guest_r15);
                break;

            default:
                goto unimplemented;
        }

        advance_rip();
        return;
    }

unimplemented:

    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "Unimplemented Control Register Access: " << std::hex << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;
    std::cout << "- control_register: 0x" << control_register << std::endl;
    std::cout << "- access_type: 0x" << access_type << std::endl;
    std::cout << "- general_purpose_register: 0x" << general_purpose_register << std::endl;
    std::cout << std::dec << std::endl;

    spin_wait();
    spin_wait();
    m_intrinsics->halt();
}

void
exit_handler_dispatch::handle_mov_dr()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_io_instruction()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_rdmsr()
{
    guest_read_msr();
    advance_rip();
}

void
exit_handler_dispatch::handle_wrmsr()
{
    guest_write_msr();
    advance_rip();
}

void
exit_handler_dispatch::handle_vm_entry_failure_invalid_guest_state()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vm_entry_failure_msr_loading()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_mwait()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_monitor_trap_flag()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_monitor()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_pause()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vm_entry_failure_machine_check_event()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_tpr_below_threshold()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_apic_access()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_virtualized_eoi()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_access_to_gdtr_or_idtr()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_access_to_ldtr_or_tr()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_ept_violation()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_ept_misconfiguration()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_invept()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_rdtscp()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmx_preemption_timer_expired()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_invvpid()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_wbinvd()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_xsetbv()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_apic_write()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_rdrand()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_invpcid()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_vmfunc()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_rdseed()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_xsaves()
{ unimplemented_handler(); }

void
exit_handler_dispatch::handle_xrstors()
{ unimplemented_handler(); }

void
exit_handler_dispatch::advance_rip()
{
    g_guest_rip += m_exit_instruction_length;
}

void
exit_handler_dispatch::spin_wait()
{
    for (auto i = 0; i < 1000000; i++);
}

void
exit_handler_dispatch::unimplemented_handler()
{
    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "Guest register state: " << std::hex << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;
    std::cout << "g_guest_rax: 0x" << g_guest_rax << std::endl;
    std::cout << "g_guest_rbx: 0x" << g_guest_rbx << std::endl;
    std::cout << "g_guest_rcx: 0x" << g_guest_rcx << std::endl;
    std::cout << "g_guest_rdx: 0x" << g_guest_rdx << std::endl << std::endl;
    std::cout << "g_guest_rsi: 0x" << g_guest_rsi << std::endl;
    std::cout << "g_guest_rdi: 0x" << g_guest_rdi << std::endl << std::endl;
    std::cout << "g_guest_rsp: 0x" << g_guest_rsp << std::endl;
    std::cout << "g_guest_rbp: 0x" << g_guest_rbp << std::endl;
    std::cout << "g_guest_rip: 0x" << g_guest_rip << std::endl;

    std::cout << std::endl;
    std::cout << std::endl;
    std::cout << "Unimplemented Exit Handler: " << std::hex << std::endl;
    std::cout << "----------------------------------------------------------------------" << std::endl;
    std::cout << "- exit reason: 0x" << m_exit_reason << " = " << exit_reason_to_str(m_exit_reason) << std::endl;
    std::cout << "- instruction length: 0x" << m_exit_instruction_length << std::endl;
    std::cout << "- instruction information: 0x" << m_exit_instruction_information << std::endl;
    std::cout << std::dec << std::endl;

    spin_wait();
    spin_wait();
    m_intrinsics->halt();
}

const char *
exit_handler_dispatch::exit_reason_to_str(uint64_t exit_reason)
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
