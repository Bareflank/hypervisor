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
#include <vmcs/vmcs_intel_x64_exceptions.h>

std::string
vmcs_intel_x64::get_vm_instruction_error()
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

uint64_t
vmcs_intel_x64::get_pin_ctls() const
{
    return vmread(VMCS_PIN_BASED_VM_EXECUTION_CONTROLS);
}

uint64_t
vmcs_intel_x64::get_proc_ctls() const
{
    return vmread(VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
}

uint64_t
vmcs_intel_x64::get_proc2_ctls() const
{
    if (is_enabled_secondary_controls() == false)
        return 0;

    return vmread(VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
}

uint64_t
vmcs_intel_x64::get_exit_ctls() const
{
    return vmread(VMCS_VM_EXIT_CONTROLS);
}

uint64_t
vmcs_intel_x64::get_entry_ctls() const
{
    return vmread(VMCS_VM_ENTRY_CONTROLS);
}

bool
vmcs_intel_x64::is_address_canonical(uint64_t addr)
{
    if (((addr <= 0x00007FFFFFFFFFFF)) ||
        ((addr >= 0xFFFF800000000000) && (addr <= 0xFFFFFFFFFFFFFFFF)))
    {
        return true;
    }

    return false;
}

bool
vmcs_intel_x64::is_linear_address_valid(uint64_t addr)
{
    return is_address_canonical(addr);
}

bool
vmcs_intel_x64::is_physical_address_valid(uint64_t addr)
{
    auto bits = (m_intrinsics->cpuid_eax(0x80000008) & 0x00000000000000FF);
    auto mask = (0xFFFFFFFFFFFFFFFFULL >> bits) << bits;

    if ((addr & mask) == 0)
        return true;

    return false;
}

bool
vmcs_intel_x64::is_cs_usable()
{
    return (vmread(VMCS_GUEST_CS_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::is_ss_usable()
{
    return (vmread(VMCS_GUEST_SS_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::is_ds_usable()
{
    return (vmread(VMCS_GUEST_DS_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::is_es_usable()
{
    return (vmread(VMCS_GUEST_ES_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::is_gs_usable()
{
    return (vmread(VMCS_GUEST_GS_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::is_fs_usable()
{
    return (vmread(VMCS_GUEST_FS_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::is_tr_usable()
{
    return (vmread(VMCS_GUEST_TR_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::is_ldtr_usable()
{
    return (vmread(VMCS_GUEST_LDTR_ACCESS_RIGHTS) & SELECTOR_UNUSABLE) == 0;
}

bool
vmcs_intel_x64::is_enabled_v8086() const
{
    return (vmread(VMCS_GUEST_RFLAGS) & RFLAGS_VM_VIRTUAL_8086_MODE) != 0;
}

bool
vmcs_intel_x64::is_enabled_external_interrupt_exiting() const
{
    auto ctls = get_pin_ctls();

    if ((ctls & VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING) == 0)
        return false;

    if (is_supported_external_interrupt_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_nmi_exiting() const
{
    auto ctls = get_pin_ctls();

    if ((ctls & VM_EXEC_PIN_BASED_NMI_EXITING) == 0)
        return false;

    if (is_supported_nmi_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_virtual_nmis() const
{
    auto ctls = get_pin_ctls();

    if ((ctls & VM_EXEC_PIN_BASED_VIRTUAL_NMIS) == 0)
        return false;

    if (is_supported_virtual_nmis() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_vmx_preemption_timer() const
{
    auto ctls = get_pin_ctls();

    if ((ctls & VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER) == 0)
        return false;

    if (is_supported_vmx_preemption_timer() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_posted_interrupts() const
{
    auto ctls = get_pin_ctls();

    if ((ctls & VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS) == 0)
        return false;

    if (is_supported_posted_interrupts() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_interrupt_window_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_INTERRUPT_WINDOW_EXITING) == 0)
        return false;

    if (is_supported_interrupt_window_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_tsc_offsetting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_USE_TSC_OFFSETTING) == 0)
        return false;

    if (is_supported_tsc_offsetting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_hlt_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_HLT_EXITING) == 0)
        return false;

    if (is_supported_hlt_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_invlpg_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_INVLPG_EXITING) == 0)
        return false;

    if (is_supported_invlpg_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_mwait_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_MWAIT_EXITING) == 0)
        return false;

    if (is_supported_mwait_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_rdpmc_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_RDPMC_EXITING) == 0)
        return false;

    if (is_supported_rdpmc_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_rdtsc_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_RDTSC_EXITING) == 0)
        return false;

    if (is_supported_rdtsc_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_cr3_load_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_CR3_LOAD_EXITING) == 0)
        return false;

    if (is_supported_cr3_load_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_cr3_store_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_CR3_STORE_EXITING) == 0)
        return false;

    if (is_supported_cr3_store_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_cr8_load_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_CR8_LOAD_EXITING) == 0)
        return false;

    if (is_supported_cr8_load_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_cr8_store_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_CR8_STORE_EXITING) == 0)
        return false;

    if (is_supported_cr8_store_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_tpr_shadow() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW) == 0)
        return false;

    if (is_supported_tpr_shadow() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_nmi_window_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING) == 0)
        return false;

    if (is_supported_nmi_window_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_mov_dr_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_MOV_DR_EXITING) == 0)
        return false;

    if (is_supported_mov_dr_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_unconditional_io_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_UNCONDITIONAL_IO_EXITING) == 0)
        return false;

    if (is_supported_unconditional_io_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_io_bitmaps() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS) == 0)
        return false;

    if (is_supported_io_bitmaps() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_monitor_trap_flag() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG) == 0)
        return false;

    if (is_supported_monitor_trap_flag() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_msr_bitmaps() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS) == 0)
        return false;

    if (is_supported_msr_bitmaps() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_monitor_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_MONITOR_EXITING) == 0)
        return false;

    if (is_supported_monitor_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_pause_exiting() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_PAUSE_EXITING) == 0)
        return false;

    if (is_supported_pause_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_secondary_controls() const
{
    auto ctls = get_proc_ctls();

    if ((ctls & VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS) == 0)
        return false;

    if (is_supported_secondary_controls() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_virtualized_apic() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES) == 0)
        return false;

    if (is_supported_virtualized_apic() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_ept() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_EPT) == 0)
        return false;

    if (is_supported_ept() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_descriptor_table_exiting() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_DESCRIPTOR_TABLE_EXITING) == 0)
        return false;

    if (is_supported_descriptor_table_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_rdtscp() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_RDTSCP) == 0)
        return false;

    if (is_supported_rdtscp() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_x2apic_mode() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE) == 0)
        return false;

    if (is_supported_x2apic_mode() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_vpid() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_VPID) == 0)
        return false;

    if (is_supported_vpid() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_wbinvd_exiting() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_WBINVD_EXITING) == 0)
        return false;

    if (is_supported_wbinvd_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_unrestricted_guests() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST) == 0)
        return false;

    if (is_supported_unrestricted_guests() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_apic_register_virtualization() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION) == 0)
        return false;

    if (is_supported_apic_register_virtualization() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_virtual_interrupt_delivery() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY) == 0)
        return false;

    if (is_supported_virtual_interrupt_delivery() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_pause_loop_exiting() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_PAUSE_LOOP_EXITING) == 0)
        return false;

    if (is_supported_pause_loop_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_rdrand_exiting() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_RDRAND_EXITING) == 0)
        return false;

    if (is_supported_rdrand_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_invpcid() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_INVPCID) == 0)
        return false;

    if (is_supported_invpcid() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_vm_functions() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS) == 0)
        return false;

    if (is_supported_vm_functions() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_vmcs_shadowing() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_VMCS_SHADOWING) == 0)
        return false;

    if (is_supported_vmcs_shadowing() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_rdseed_exiting() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_RDSEED_EXITING) == 0)
        return false;

    if (is_supported_rdseed_exiting() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_ept_violation_ve() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE) == 0)
        return false;

    if (is_supported_ept_violation_ve() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_xsave_xrestore() const
{
    auto ctls = get_proc2_ctls();

    if ((ctls & VM_EXEC_S_PROC_BASED_ENABLE_XSAVES_XRSTORS) == 0)
        return false;

    if (is_supported_xsave_xrestore() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_save_debug_controls_on_exit() const
{
    auto ctls = get_exit_ctls();

    if ((ctls & VM_EXIT_CONTROL_SAVE_DEBUG_CONTROLS) == 0)
        return false;

    if (is_supported_save_debug_controls_on_exit() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_host_address_space_size() const
{
    auto ctls = get_exit_ctls();

    if ((ctls & VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE) == 0)
        return false;

    if (is_supported_host_address_space_size() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_load_ia32_perf_global_ctrl_on_exit() const
{
    auto ctls = get_exit_ctls();

    if ((ctls & VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL) == 0)
        return false;

    if (is_supported_load_ia32_perf_global_ctrl_on_exit() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_ack_interrupt_on_exit() const
{
    auto ctls = get_exit_ctls();

    if ((ctls & VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT) == 0)
        return false;

    if (is_supported_ack_interrupt_on_exit() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_save_ia32_pat_on_exit() const
{
    auto ctls = get_exit_ctls();

    if ((ctls & VM_EXIT_CONTROL_SAVE_IA32_PAT) == 0)
        return false;

    if (is_supported_save_ia32_pat_on_exit() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_load_ia32_pat_on_exit() const
{
    auto ctls = get_exit_ctls();

    if ((ctls & VM_EXIT_CONTROL_LOAD_IA32_PAT) == 0)
        return false;

    if (is_supported_load_ia32_pat_on_exit() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_save_ia32_efer_on_exit() const
{
    auto ctls = get_exit_ctls();

    if ((ctls & VM_EXIT_CONTROL_SAVE_IA32_EFER) == 0)
        return false;

    if (is_supported_save_ia32_efer_on_exit() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_load_ia32_efer_on_exit() const
{
    auto ctls = get_exit_ctls();

    if ((ctls & VM_EXIT_CONTROL_LOAD_IA32_EFER) == 0)
        return false;

    if (is_supported_load_ia32_efer_on_exit() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_save_vmx_preemption_timer_on_exit() const
{
    auto ctls = get_exit_ctls();

    if ((ctls & VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE) == 0)
        return false;

    if (is_supported_save_vmx_preemption_timer_on_exit() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_load_debug_controls_on_entry() const
{
    auto ctls = get_entry_ctls();

    if ((ctls & VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS) == 0)
        return false;

    if (is_supported_load_debug_controls_on_entry() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_ia_32e_mode_guest() const
{
    auto ctls = get_entry_ctls();

    if ((ctls & VM_ENTRY_CONTROL_IA_32E_MODE_GUEST) == 0)
        return false;

    if (is_supported_ia_32e_mode_guest() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_entry_to_smm() const
{
    auto ctls = get_entry_ctls();

    if ((ctls & VM_ENTRY_CONTROL_ENTRY_TO_SMM) == 0)
        return false;

    if (is_supported_entry_to_smm() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_deactivate_dual_monitor_treatment() const
{
    auto ctls = get_entry_ctls();

    if ((ctls & VM_ENTRY_CONTROL_DEACTIVATE_DUAL_MONITOR_TREATMENT) == 0)
        return false;

    if (is_supported_deactivate_dual_monitor_treatment() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_load_ia32_perf_global_ctrl_on_entry() const
{
    auto ctls = get_entry_ctls();

    if ((ctls & VM_ENTRY_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL) == 0)
        return false;

    if (is_supported_load_ia32_perf_global_ctrl_on_entry() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_load_ia32_pat_on_entry() const
{
    auto ctls = get_entry_ctls();

    if ((ctls & VM_ENTRY_CONTROL_LOAD_IA32_PAT) == 0)
        return false;

    if (is_supported_load_ia32_pat_on_entry() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_enabled_load_ia32_efer_on_entry() const
{
    auto ctls = get_entry_ctls();

    if ((ctls & VM_ENTRY_CONTROL_LOAD_IA32_EFER) == 0)
        return false;

    if (is_supported_load_ia32_efer_on_entry() == false)
        throw hardware_unsupported("VMCS control not supported");

    return true;
}

bool
vmcs_intel_x64::is_supported_external_interrupt_exiting() const
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR);

    return ia32_vmx_pinbased_ctls_msr &
           (VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_nmi_exiting() const
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR);

    return ia32_vmx_pinbased_ctls_msr &
           (VM_EXEC_PIN_BASED_NMI_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_virtual_nmis() const
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR);

    return ia32_vmx_pinbased_ctls_msr &
           (VM_EXEC_PIN_BASED_VIRTUAL_NMIS << 32);
}

bool
vmcs_intel_x64::is_supported_vmx_preemption_timer() const
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR);

    return ia32_vmx_pinbased_ctls_msr &
           (VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER << 32);
}

bool
vmcs_intel_x64::is_supported_posted_interrupts() const
{
    auto ia32_vmx_pinbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PINBASED_CTLS_MSR);

    return ia32_vmx_pinbased_ctls_msr &
           (VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS << 32);
}

bool
vmcs_intel_x64::is_supported_interrupt_window_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_INTERRUPT_WINDOW_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_tsc_offsetting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_USE_TSC_OFFSETTING << 32);
}

bool
vmcs_intel_x64::is_supported_hlt_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_HLT_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_invlpg_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_INVLPG_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_mwait_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_MWAIT_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_rdpmc_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_RDPMC_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_rdtsc_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_RDTSC_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_cr3_load_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_CR3_LOAD_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_cr3_store_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_CR3_STORE_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_cr8_load_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_CR8_LOAD_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_cr8_store_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_CR8_STORE_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_tpr_shadow() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW << 32);
}

bool
vmcs_intel_x64::is_supported_nmi_window_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_mov_dr_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_MOV_DR_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_unconditional_io_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_UNCONDITIONAL_IO_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_io_bitmaps() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS << 32);
}

bool
vmcs_intel_x64::is_supported_monitor_trap_flag() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32);
}

bool
vmcs_intel_x64::is_supported_msr_bitmaps() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG << 32);
}

bool
vmcs_intel_x64::is_supported_monitor_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_MONITOR_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_pause_exiting() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_PAUSE_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_secondary_controls() const
{
    auto ia32_vmx_procbased_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_PROCBASED_CTLS_MSR);

    return ia32_vmx_procbased_ctls_msr &
           (VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS << 32);
}

bool
vmcs_intel_x64::is_supported_virtualized_apic() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES << 32);
}

bool
vmcs_intel_x64::is_supported_ept() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_EPT << 32);
}

bool
vmcs_intel_x64::is_supported_descriptor_table_exiting() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_DESCRIPTOR_TABLE_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_rdtscp() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_RDTSCP << 32);
}

bool
vmcs_intel_x64::is_supported_x2apic_mode() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE << 32);
}

bool
vmcs_intel_x64::is_supported_vpid() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_VPID << 32);
}

bool
vmcs_intel_x64::is_supported_wbinvd_exiting() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_WBINVD_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_unrestricted_guests() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST << 32);
}

bool
vmcs_intel_x64::is_supported_apic_register_virtualization() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION << 32);
}

bool
vmcs_intel_x64::is_supported_virtual_interrupt_delivery() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY << 32);
}

bool
vmcs_intel_x64::is_supported_pause_loop_exiting() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_PAUSE_LOOP_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_rdrand_exiting() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_RDRAND_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_invpcid() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_INVPCID << 32);
}

bool
vmcs_intel_x64::is_supported_vm_functions() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS << 32);
}

bool
vmcs_intel_x64::is_supported_vmcs_shadowing() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_VMCS_SHADOWING << 32);
}

bool
vmcs_intel_x64::is_supported_rdseed_exiting() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_RDSEED_EXITING << 32);
}

bool
vmcs_intel_x64::is_supported_ept_violation_ve() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE << 32);
}

bool
vmcs_intel_x64::is_supported_xsave_xrestore() const
{
    auto ia32_vmx_procbased_ctls2_msr =
        m_intrinsics->read_msr(IA32_VMX_PROCBASED_CTLS2_MSR);

    return ia32_vmx_procbased_ctls2_msr &
           (VM_EXEC_S_PROC_BASED_ENABLE_XSAVES_XRSTORS << 32);
}

bool
vmcs_intel_x64::is_supported_save_debug_controls_on_exit() const
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_SAVE_DEBUG_CONTROLS << 32);
}

bool
vmcs_intel_x64::is_supported_host_address_space_size() const
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_HOST_ADDRESS_SPACE_SIZE << 32);
}

bool
vmcs_intel_x64::is_supported_load_ia32_perf_global_ctrl_on_exit() const
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL << 32);
}

bool
vmcs_intel_x64::is_supported_ack_interrupt_on_exit() const
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT << 32);
}

bool
vmcs_intel_x64::is_supported_save_ia32_pat_on_exit() const
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_SAVE_IA32_PAT << 32);
}

bool
vmcs_intel_x64::is_supported_load_ia32_pat_on_exit() const
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_LOAD_IA32_PAT << 32);
}

bool
vmcs_intel_x64::is_supported_save_ia32_efer_on_exit() const
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_SAVE_IA32_EFER << 32);
}

bool
vmcs_intel_x64::is_supported_load_ia32_efer_on_exit() const
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_LOAD_IA32_EFER << 32);
}

bool
vmcs_intel_x64::is_supported_save_vmx_preemption_timer_on_exit() const
{
    auto ia32_vmx_exit_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_EXIT_CTLS_MSR);

    return ia32_vmx_exit_ctls_msr &
           (VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE << 32);
}

bool
vmcs_intel_x64::is_supported_load_debug_controls_on_entry() const
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS << 32);
}

bool
vmcs_intel_x64::is_supported_ia_32e_mode_guest() const
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_IA_32E_MODE_GUEST << 32);
}

bool
vmcs_intel_x64::is_supported_entry_to_smm() const
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_ENTRY_TO_SMM << 32);
}

bool
vmcs_intel_x64::is_supported_deactivate_dual_monitor_treatment() const
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_DEACTIVATE_DUAL_MONITOR_TREATMENT << 32);
}

bool
vmcs_intel_x64::is_supported_load_ia32_perf_global_ctrl_on_entry() const
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL << 32);
}

bool
vmcs_intel_x64::is_supported_load_ia32_pat_on_entry() const
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_LOAD_IA32_PAT << 32);
}

bool
vmcs_intel_x64::is_supported_load_ia32_efer_on_entry() const
{
    auto ia32_vmx_entry_ctls_msr =
        m_intrinsics->read_msr(IA32_VMX_TRUE_ENTRY_CTLS_MSR);

    return ia32_vmx_entry_ctls_msr &
           (VM_ENTRY_CONTROL_LOAD_IA32_EFER << 32);
}

bool
vmcs_intel_x64::is_supported_eptp_switching() const
{
    if (this->is_supported_secondary_controls() == false)
        return false;

    if (this->is_supported_vm_functions() == false)
        return false;

    return (vmread(VMCS_VM_FUNCTION_CONTROLS_FULL) &
            VM_FUNCTION_CONTROL_EPTP_SWITCHING);
}

bool
vmcs_intel_x64::check_pat(uint64_t pat)
{
    switch (pat)
    {
        case 0:
        case 1:
        case 4:
        case 5:
        case 6:
        case 7:
            return true;

        default:
            return false;
    }
}
