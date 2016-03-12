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

#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_checks.h>
#include <vmcs/vmcs_intel_x64_exceptions.h>

std::string
vmcs_intel_x64::check_vm_instruction_error()
{
    switch (vmread(VMCS_VM_INSTRUCTION_ERROR))
    {
        case 1:
            return "VMCALL executed in VMX root operation";

        case 2:
            return "VMCLEAR with invalid physical address";

        case 3:
            return "VMCLEAR with VMXON pointer";

        case 4:
            return "VMLAUNCH with non-clear VMCS";

        case 5:
            return "VMRESUME with non-launched VMCS";

        case 6:
            return "VMRESUME after VMXOFF (VMXOFF and VMXON between "
                   "VMLAUNCH and VMRESUME)";

        case 7:
            return "VM entry with invalid control field(s)";

        case 8:
            return "VM entry with invalid host-state field(s)";

        case 9:
            return "VMPTRLD with invalid physical address";

        case 10:
            return "VMPTRLD with VMXON pointer";

        case 11:
            return "VMPTRLD with incorrect VMCS revision identifier";

        case 12:
            return "VMREAD/VMWRITE from/to unsupported VMCS component";

        case 13:
            return "VMWRITE to read-only VMCS component";

        case 15:
            return "VMXON executed in VMX root operation";

        case 16:
            return "VM entry with invalid executive-VMCS pointer";

        case 17:
            return "VM entry with non-launched executive VMCS";

        case 18:
            return "VM entry with executive-VMCS pointer not VMXON "
                   "pointer (when attempting to deactivate the "
                   "dual-monitor treatment of SMIs and SMM)";

        case 19:
            return "VMCALL with non-clear VMCS (when attempting to "
                   "activate the dual-monitor treatment of SMIs and "
                   "SMM)";

        case 20:
            return "VMCALL with invalid VM-exit control fields";

        case 22:
            return "VMCALL with incorrect MSEG revision identifier "
                   "(when attempting to activate the dual-monitor "
                   "treatment of SMIs and SMM)";

        case 23:
            return "VMXOFF under dual-monitor treatment of SMIs and "
                   "SMM";

        case 24:
            return "VMCALL with invalid SMM-monitor features (when "
                   "attempting to activate the dual-monitor treatment "
                   "of SMIs and SMM)";

        case 25:
            return "VM entry with invalid VM-execution control fields "
                   "in executive VMCS (when attempting to return from "
                   "SMM)";

        case 26:
            return "VM entry with events blocked by MOV SS.";

        case 28:
            return "Invalid operand to INVEPT/INVVPID.";

        default:
            return "Unknown VM instruction error";
    }
}

bool
vmcs_intel_x64::check_is_address_canonical(uint64_t addr)
{
    if (((addr <= 0x00007FFFFFFFFFFF)) ||
        ((addr >= 0xFFFF800000000000) && (addr <= 0xFFFFFFFFFFFFFFFF)))
    {
        return true;
    }

    return false;
}

bool
vmcs_intel_x64::check_has_valid_address_width(uint64_t addr)
{
    auto bits = (m_intrinsics->cpuid_eax(0x80000008) & 0x00000000000000FF);
    auto mask = (0xFFFFFFFFFFFFFFFFULL >> bits) << bits;

    if ((addr & mask) == 0)
        return true;

    return false;
}

bool
vmcs_intel_x64::check_is_v8086_enabled()
{
    return (vmread(VMCS_GUEST_RFLAGS) & RFLAGS_VM_VIRTUAL_8086_MODE) != 0;
}

bool
vmcs_intel_x64::check_is_unrestricted_enabled()
{
    auto ctls = get_proc2_ctls();

    if proc2_enabled(ctls, VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST)
        return true;

    return false;
}

bool
vmcs_intel_x64::check_is_ia32e_mode_enabled()
{
    auto ctls = get_entry_ctls();

    if entry_enabled(ctls, VM_ENTRY_CONTROL_IA_32E_MODE_GUEST)
        return true;

    return false;
}

bool
vmcs_intel_x64::check_is_cs_usable()
{
    return (vmread(VMCS_GUEST_CS_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::check_is_ss_usable()
{
    return (vmread(VMCS_GUEST_SS_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::check_is_ds_usable()
{
    return (vmread(VMCS_GUEST_DS_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::check_is_es_usable()
{
    return (vmread(VMCS_GUEST_ES_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::check_is_gs_usable()
{
    return (vmread(VMCS_GUEST_GS_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::check_is_fs_usable()
{
    return (vmread(VMCS_GUEST_FS_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::check_is_tr_usable()
{
    return (vmread(VMCS_GUEST_TR_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::check_is_ldtr_usable()
{
    return (vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::check_vmcs_host_state()
{
    auto result = true;

    result &= check_host_control_registers_and_msrs();
    result &= check_host_segment_and_descriptor_table_registers();
    result &= check_host_checks_related_to_address_space_size();

    return result;
}

bool
vmcs_intel_x64::supports_external_interrupt_exiting()
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PINBASED_CTLS_MSR);

    return ia32_vmx_pinbased_ctls_msr &
           (VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING << 32);
}

bool
vmcs_intel_x64::supports_nmi_exiting()
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PINBASED_CTLS_MSR);

    return ia32_vmx_pinbased_ctls_msr &
           (VM_EXEC_PIN_BASED_NMI_EXITING << 32);
}

bool
vmcs_intel_x64::supports_virtual_nmis()
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PINBASED_CTLS_MSR);

    return ia32_vmx_pinbased_ctls_msr &
           (VM_EXEC_PIN_BASED_VIRTUAL_NMIS << 32);
}

bool
vmcs_intel_x64::supports_vmx_preemption_timer()
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PINBASED_CTLS_MSR);

    return ia32_vmx_pinbased_ctls_msr &
           (VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER << 32);
}

bool
vmcs_intel_x64::supports_posted_interrupts()
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PINBASED_CTLS_MSR);

    return ia32_vmx_pinbased_ctls_msr &
           (VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS << 32);
}

bool
vmcs_intel_x64::supports_interrupt_window_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_INTERRUPT_WINDOW_EXITING << 32);
}

bool
vmcs_intel_x64::supports_tsc_offsetting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_USE_TSC_OFFSETTING << 32);
}

bool
vmcs_intel_x64::supports_hlt_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_HLT_EXITING << 32);
}

bool
vmcs_intel_x64::supports_invlpg_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_INVLPG_EXITING << 32);
}

bool
vmcs_intel_x64::supports_mwait_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_MWAIT_EXITING << 32);
}

bool
vmcs_intel_x64::supports_rdpmc_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_RDPMC_EXITING << 32);
}

bool
vmcs_intel_x64::supports_rdtsc_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_RDTSC_EXITING << 32);
}

bool
vmcs_intel_x64::supports_cr3_load_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_CR3_LOAD_EXITING << 32);
}

bool
vmcs_intel_x64::supports_cr3_store_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_CR3_STORE_EXITING << 32);
}

bool
vmcs_intel_x64::supports_cr8_load_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_CR8_LOAD_EXITING << 32);
}

bool
vmcs_intel_x64::supports_cr8_store_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_CR8_STORE_EXITING << 32);
}

bool
vmcs_intel_x64::supports_tpr_shadow()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32);
}

bool
vmcs_intel_x64::supports_nmi_window_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING << 32);
}

bool
vmcs_intel_x64::supports_mov_dr_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_MOV_DR_EXITING << 32);
}

bool
vmcs_intel_x64::supports_unconditional_io_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_UNCONDITIONAL_IO_EXITING << 32);
}

bool
vmcs_intel_x64::supports_io_bitmaps()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS << 32);
}

bool
vmcs_intel_x64::supports_monitor_trap_flag()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32);
}

bool
vmcs_intel_x64::supports_msr_bitmaps()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32);
}

bool
vmcs_intel_x64::supports_monitor_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_MONITOR_EXITING << 32);
}

bool
vmcs_intel_x64::supports_pause_exiting()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_PAUSE_EXITING << 32);
}

bool
vmcs_intel_x64::supports_secondary_controls()
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32);
}

bool
vmcs_intel_x64::supports_virtualized_apic()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32);
}

bool
vmcs_intel_x64::supports_ept()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32);
}

bool
vmcs_intel_x64::supports_descriptor_table_exiting()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_DESCRIPTOR_TABLE_EXITING << 32);
}

bool
vmcs_intel_x64::supports_rdtscp()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_RDTSCP << 32);
}

bool
vmcs_intel_x64::supports_x2apic_mode()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE << 32);
}

bool
vmcs_intel_x64::supports_vpid()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_VPID << 32);
}

bool
vmcs_intel_x64::supports_wbinvd_exiting()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_WBINVD_EXITING << 32);
}

bool
vmcs_intel_x64::supports_unrestricted_guests()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32);
}

bool
vmcs_intel_x64::supports_apic_register_virtualization()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION << 32);
}

bool
vmcs_intel_x64::supports_virtual_interrupt_delivery()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32);
}

bool
vmcs_intel_x64::supports_pause_loop_exiting()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_PAUSE_LOOP_EXITING << 32);
}

bool
vmcs_intel_x64::supports_rdrand_exiting()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_RDRAND_EXITING << 32);
}

bool
vmcs_intel_x64::supports_invpcid()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_INVPCID << 32);
}

bool
vmcs_intel_x64::supports_vm_functions()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS << 32);
}

bool
vmcs_intel_x64::supports_vmcs_shadowing()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_VMCS_SHADOWING << 32);
}

bool
vmcs_intel_x64::supports_rdseed_exiting()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_RDSEED_EXITING << 32);
}

bool
vmcs_intel_x64::supports_ept_violation_ve()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE << 32);
}

bool
vmcs_intel_x64::supports_xsave_xrestore()
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_XSAVES_XRSTORS << 32);
}

bool
vmcs_intel_x64::supports_save_debug_controls_on_exit()
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_SAVE_DEBUG_CONTROLS << 32);
}

bool
vmcs_intel_x64::supports_host_address_space_size()
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32);
}

bool
vmcs_intel_x64::supports_load_ia32_perf_global_ctrl_on_exit()
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL << 32);
}

bool
vmcs_intel_x64::supports_ack_interrupt_on_exit()
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT << 32);
}

bool
vmcs_intel_x64::supports_save_ia32_pat_on_exit()
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_SAVE_IA32_PAT << 32);
}

bool
vmcs_intel_x64::supports_load_ia32_pat_on_exit()
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_LOAD_IA32_PAT << 32);
}

bool
vmcs_intel_x64::supports_save_ia32_efer_on_exit()
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_SAVE_IA32_EFER << 32);
}

bool
vmcs_intel_x64::supports_load_ia32_efer_on_exit()
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_LOAD_IA32_EFER << 32);
}

bool
vmcs_intel_x64::supports_save_vmx_preemption_timer_on_exit()
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE << 32);
}

bool
vmcs_intel_x64::supports_load_debug_controls_on_entry()
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS << 32);
}

bool
vmcs_intel_x64::supports_ia_32e_mode_guest()
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32);
}

bool
vmcs_intel_x64::supports_entry_to_smm()
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_ENTRY_TO_SMM << 32);
}

bool
vmcs_intel_x64::supports_deactivate_dual_monitor_treatment()
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_DEACTIVATE_DUAL_MONITOR_TREATMENT << 32);
}

bool
vmcs_intel_x64::supports_load_ia32_perf_global_ctrl_on_entry()
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL << 32);
}

bool
vmcs_intel_x64::supports_load_ia32_pat_on_entry()
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_LOAD_IA32_PAT << 32);
}

bool
vmcs_intel_x64::supports_load_ia32_efer_on_entry()
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_LOAD_IA32_EFER << 32);
}

bool
vmcs_intel_x64::supports_eptp_switching()
{
    if (this->supports_secondary_controls() == false)
        return false;

    if (this->supports_vm_functions() == false)
        return false;

    return (vmread(VMCS_VM_FUNCTION_CONTROLS_FULL) &
            VM_FUNCTION_CONTROL_EPTP_SWITCHING);
}
