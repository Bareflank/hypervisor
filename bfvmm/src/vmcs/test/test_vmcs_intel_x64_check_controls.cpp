//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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

#include <test.h>

static struct control_flow_path path;

static void
setup_check_control_pin_based_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[IA32_VMX_TRUE_PINBASED_CTLS_MSR] = 0; g_vmcs_fields[VMCS_PIN_BASED_VM_EXECUTION_CONTROLS] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[IA32_VMX_TRUE_PINBASED_CTLS_MSR] = 1; g_vmcs_fields[VMCS_PIN_BASED_VM_EXECUTION_CONTROLS] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid pin based controls"));
    cfg.push_back(path);

}

static void
setup_check_control_proc_based_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[IA32_VMX_TRUE_PROCBASED_CTLS_MSR] = 0; g_vmcs_fields[VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[IA32_VMX_TRUE_PROCBASED_CTLS_MSR] = 1; g_vmcs_fields[VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid proc based controls"));
    cfg.push_back(path);
}

static void
setup_check_control_proc_based_ctls2_reserved_properly_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[IA32_VMX_PROCBASED_CTLS2_MSR] = 0; g_vmcs_fields[VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[IA32_VMX_PROCBASED_CTLS2_MSR] = 1; g_vmcs_fields[VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid proc based secondary controls"));
    cfg.push_back(path);
}

static void
setup_check_control_cr3_count_less_than_4_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_CR3_TARGET_COUNT] = 3; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_CR3_TARGET_COUNT] = 5; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("cr3 target count > 4"));
    cfg.push_back(path);
}

static void
setup_check_control_io_bitmap_address_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl(VM_EXEC_P_PROC_BASED_USE_IO_BITMAPS); g_vmcs_fields[VMCS_ADDRESS_OF_IO_BITMAP_A_FULL] = 0x1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("io bitmap a addr not page aligned"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_ADDRESS_OF_IO_BITMAP_A_FULL] = 0xff00000000000000; g_vmcs_fields[VMCS_ADDRESS_OF_IO_BITMAP_B_FULL] = 0x1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("io bitmap b addr not page aligned"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_ADDRESS_OF_IO_BITMAP_B_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("io bitmap a addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_ADDRESS_OF_IO_BITMAP_A_FULL] = 0x1000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("io bitmap b addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_ADDRESS_OF_IO_BITMAP_B_FULL] = 0x1000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_msr_bitmap_address_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl(VM_EXEC_P_PROC_BASED_USE_MSR_BITMAPS); g_vmcs_fields[VMCS_ADDRESS_OF_MSR_BITMAPS_FULL] = 0x1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("msr bitmap addr not page aligned"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_ADDRESS_OF_MSR_BITMAPS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("msr bitmap addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_ADDRESS_OF_MSR_BITMAPS_FULL] = 0x1000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_tpr_shadow_and_virtual_apic_paths(std::vector<struct control_flow_path> &cfg)
{
    // control paths when tpr shadow is enabled
    path.setup = [&] { enable_proc_ctl(VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW); g_vmcs_fields[VMCS_VIRTUAL_APIC_ADDRESS_FULL] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual apic physical addr is NULL"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VIRTUAL_APIC_ADDRESS_FULL] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual apic addr not 4k aligned"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VIRTUAL_APIC_ADDRESS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual apic addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VIRTUAL_APIC_ADDRESS_FULL] = 0x1000; enable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("tpr_shadow is enabled, but virtual interrupt delivery is enabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY); g_vmcs_fields[VMCS_TPR_THRESHOLD] = 0xffffffffffffffff; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 31:4 of the tpr threshold must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_TPR_THRESHOLD] = 0; enable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("tpr_shadow is enabled, but virtual apic is enabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES); g_phys_to_virt_return_nullptr = true; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual apic virtual addr is NULL"));
    cfg.push_back(path);

    path.setup = [&] { g_phys_to_virt_return_nullptr = false; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_TPR_THRESHOLD] = 0xf; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid TPR threshold"));
    cfg.push_back(path);

    // control paths when tpr shadow is disabled
    path.setup = [&] { disable_proc_ctl(VM_EXEC_P_PROC_BASED_USE_TPR_SHADOW); enable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("x2apic mode must be disabled if tpr shadow is disabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE); enable_proc_ctl2(VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("apic register virtualization must be disabled if tpr shadow is disabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_APIC_REGISTER_VIRTUALIZATION); enable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual interrupt delivery must be disabled if tpr shadow is disabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_nmi_exiting_and_virtual_nmi_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_pin_ctl(VM_EXEC_PIN_BASED_NMI_EXITING); enable_pin_ctl(VM_EXEC_PIN_BASED_VIRTUAL_NMIS); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual NMI must be 0 if NMI exiting is 0"));
    cfg.push_back(path);

    path.setup = [&] { enable_pin_ctl(VM_EXEC_PIN_BASED_NMI_EXITING); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_virtual_nmi_and_nmi_window_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_pin_ctl(VM_EXEC_PIN_BASED_VIRTUAL_NMIS); enable_proc_ctl(VM_EXEC_P_PROC_BASED_NMI_WINDOW_EXITING); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("NMI window exitin must be 0 if virtual NMI is 0"));
    cfg.push_back(path);

    path.setup = [&] { enable_pin_ctl(VM_EXEC_PIN_BASED_VIRTUAL_NMIS); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_virtual_apic_address_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES); g_vmcs_fields[VMCS_APIC_ACCESS_ADDRESS_FULL] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("apic access physical addr is NULL"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_APIC_ACCESS_ADDRESS_FULL] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("apic access addr not 4k aligned"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_APIC_ACCESS_ADDRESS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("apic access addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_APIC_ACCESS_ADDRESS_FULL] = 0x1000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_x2apic_mode_and_virtual_apic_access_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE); enable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUALIZE_APIC_ACCESSES); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("apic accesses must be 0 if x2 apic mode is 1"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUALIZE_X2APIC_MODE); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_virtual_interrupt_and_external_interrupt_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY); disable_pin_ctl(VM_EXEC_PIN_BASED_EXTERNAL_INTERRUPT_EXITING); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("external interrupt exiting must be 1 if virtual interrupt delivery is 1"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_process_posted_interrupt_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_pin_ctl(VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_pin_ctl(VM_EXEC_PIN_BASED_PROCESS_POSTED_INTERRUPTS); disable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual interrupt delivery must be 1 if posted interrupts is 1"));
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_VIRTUAL_INTERRUPT_DELIVERY); disable_exit_ctl(VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("ack interrupt on exit must be 1 if posted interrupts is 1"));
    cfg.push_back(path);

    path.setup = [&] { enable_exit_ctl(VM_EXIT_CONTROL_ACKNOWLEDGE_INTERRUPT_ON_EXIT); g_vmcs_fields[VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR] = 0x100; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 15:8 of the notification vector must be 0 if posted interrupts is 1"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR] = 0; g_vmcs_fields[VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 5:0 of the interrupt descriptor addr must be 0 if posted interrupts is 1"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt descriptor addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL] = 0x1000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_vpid_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_VPID); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_VPID); g_vmcs_fields[VMCS_VIRTUAL_PROCESSOR_IDENTIFIER] = 0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("vpid cannot equal 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VIRTUAL_PROCESSOR_IDENTIFIER] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_ept_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_EPT); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_EPT);
        g_vmcs_fields[VMCS_EPT_POINTER_FULL] = 0;
        g_msrs[IA32_VMX_EPT_VPID_CAP_MSR] = ~(IA32_VMX_EPT_VPID_CAP_UC | IA32_VMX_EPT_VPID_CAP_WB);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("hardware does not support ept memory type: uncachable"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_EPT_POINTER_FULL] = 6; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("hardware does not support ept memory type: write-back"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_EPT_POINTER_FULL] = 3; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("unknown eptp memory type"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_EPT_POINTER_FULL] = 0xfe; g_msrs[IA32_VMX_EPT_VPID_CAP_MSR] = IA32_VMX_EPT_VPID_CAP_WB; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("the ept walk-through length must be 1 less than 4, i.e. 3"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_EPT_POINTER_FULL] = 0x5e; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("hardware does not support dirty / accessed flags for ept"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_EPT_POINTER_FULL] = 0x9e; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:7 and 63:48 of the eptp must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_EPT_POINTER_FULL] = 0xf00000000000001e; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("eptp must be a valid physical address"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_EPT_POINTER_FULL] = 0x1e; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_pml_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_PML); disable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_EPT); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("ept must be enabled if pml is enabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_PML); g_vmcs_fields[VMCS_PML_ADDRESS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pml address must be a valid physical address"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_PML_ADDRESS_FULL] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:0 of the pml address must be 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_PML_ADDRESS_FULL] = 0x1000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_unrestricted_guests_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST); disable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_EPT); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("enable ept must be 1 if unrestricted guest is 1"));
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_EPT); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_vm_functions_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_VM_FUNCTIONS);
        g_vmcs_fields[VMCS_VM_FUNCTION_CONTROLS_FULL] = 1;
        g_msrs[IA32_VMX_VMFUNC_MSR] = 0;
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("unsupported vm function control bit set"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_FUNCTION_CONTROLS_FULL] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_vmcs_fields[VMCS_VM_FUNCTION_CONTROLS_FULL] = VM_FUNCTION_CONTROL_EPTP_SWITCHING;
        g_msrs[IA32_VMX_VMFUNC_MSR] = VM_FUNCTION_CONTROL_EPTP_SWITCHING;
        disable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_EPT);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("enable ept must be 1 if eptp switching is 1"));
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_ENABLE_EPT); g_vmcs_fields[VMCS_EPTP_LIST_ADDRESS_FULL] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:0 must be 0 for eptp list address"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_EPTP_LIST_ADDRESS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("eptp list address addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_EPTP_LIST_ADDRESS_FULL] = 0x1000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_vmcs_shadowing_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_VMCS_SHADOWING); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_VMCS_SHADOWING); g_vmcs_fields[VMCS_VMREAD_BITMAP_ADDRESS_FULL] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:0 must be 0 for the vmcs read bitmap address"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VMREAD_BITMAP_ADDRESS_FULL] = 0xff00000000000000; g_vmcs_fields[VMCS_VMWRITE_BITMAP_ADDRESS_FULL] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:0 must be 0 for the vmcs write bitmap address"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VMWRITE_BITMAP_ADDRESS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("vmcs read bitmap address addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VMREAD_BITMAP_ADDRESS_FULL] = 0x1000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("vmcs write bitmap address addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VMWRITE_BITMAP_ADDRESS_FULL] = 0x1000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_ept_violation_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl2(VM_EXEC_S_PROC_BASED_EPT_VIOLATION_VE); g_vmcs_fields[VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:0 must be 0 for the vmcs virt except info address"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("vmcs virt except info address addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL] = 0x1000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_vm_exit_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_CONTROLS] = 0; g_msrs[IA32_VMX_TRUE_EXIT_CTLS_MSR] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid exit controls"));
    cfg.push_back(path);

    path.setup = [&] { g_msrs[IA32_VMX_TRUE_EXIT_CTLS_MSR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_activate_and_save_preemption_timer_must_be_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_pin_ctl(VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER); enable_exit_ctl(VM_EXIT_CONTROL_SAVE_VMX_PREEMPTION_TIMER_VALUE); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("save vmx preemption timer must be 0 if activate vmx preemption timer is 0"));
    cfg.push_back(path);

    path.setup = [&] { enable_pin_ctl(VM_EXEC_PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_exit_msr_store_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_MSR_STORE_COUNT] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_MSR_STORE_COUNT] = 16; g_vmcs_fields[VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL] = 0xf; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 3:0 must be 0 for the exit msr store address"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("exit msr store addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL] = 0xfffffff0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("end of exit msr store area too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL] = 0x10; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_exit_msr_load_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_MSR_LOAD_COUNT] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_MSR_LOAD_COUNT] = 16; g_vmcs_fields[VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL] = 0xf; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 3:0 must be 0 for the exit msr load address"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("exit msr load addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL] = 0xfffffff0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("end of exit msr load area too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL] = 0x10; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_vm_entry_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_CONTROLS] = 0; g_msrs[IA32_VMX_TRUE_ENTRY_CTLS_MSR] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid entry controls"));
    cfg.push_back(path);

    path.setup = [&] { g_msrs[IA32_VMX_TRUE_ENTRY_CTLS_MSR] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_type_vector_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = 0x100 | VM_INTERRUPT_INFORMATION_VALID; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field type of 1 is reserved"));
    cfg.push_back(path);

    path.setup = [&]
    {
        g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = 0x700 | VM_INTERRUPT_INFORMATION_VALID;
        disable_proc_ctl(VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field type of 7 is reserved on this hardware"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = 0x200 | VM_INTERRUPT_INFORMATION_VALID | VM_INTERRUPT_INFORMATION_VECTOR; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field vector must be 2 if the type field is 2 (NMI)"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] |= 0x300; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field vector must be 0->31 if the type field is 3 (HE)"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] |= 0x700; enable_proc_ctl(VM_EXEC_P_PROC_BASED_MONITOR_TRAP_FLAG); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field vector must be 0 if the type field is 7 (other)"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = 0x202 | VM_INTERRUPT_INFORMATION_VALID; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_delivery_ec_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = VM_INTERRUPT_INFORMATION_VALID; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] |= VM_INTERRUPT_INFORMATION_DELIVERY_ERROR;
        g_vmcs_fields[VMCS_GUEST_CR0] = 0;
        enable_proc_ctl2(VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("unrestricted guest must be 0 or PE must be enabled in cr0"
                     "if deliver error code bit is set"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(VM_EXEC_S_PROC_BASED_UNRESTRICTED_GUEST); g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] |= 0x200; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field type must be 3 if deliver error code bit is set"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = 0x300 | VM_INTERRUPT_INFORMATION_VALID | VM_INTERRUPT_INFORMATION_DELIVERY_ERROR; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("vector must indicate exception that would normally deliver"
                     "an error code if deliver error code bit is set"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] |= 0x8; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_reserved_bits_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = VM_INTERRUPT_INFORMATION_VALID; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] |= 0x1000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("reserved bits of the interrupt info field must be 0"));
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_ec_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = VM_INTERRUPT_INFORMATION_VALID; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] |= VM_INTERRUPT_INFORMATION_DELIVERY_ERROR;
        g_vmcs_fields[VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE] = 0x8000;
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 31:15 of the exception error code field must be 0"
                     " if deliver error code bit is set in the interrupt info field"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_instr_length_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = VM_INTERRUPT_INFORMATION_VALID | 0x700; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = VM_INTERRUPT_INFORMATION_VALID | 0x400;
        g_vmcs_fields[VMCS_VM_ENTRY_INSTRUCTION_LENGTH] = 0;
        g_msrs[IA32_VMX_MISC_MSR] = 0;
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("instruction length must be greater than zero"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INSTRUCTION_LENGTH] = 16; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("instruction length must be in the range of 0-15 if type is 4, 5, 6"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_INSTRUCTION_LENGTH] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_entry_msr_load_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_MSR_LOAD_COUNT] = 0; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_MSR_LOAD_COUNT] = 16; g_vmcs_fields[VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL] = 0xf; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 3:0 must be 0 for the entry msr load address"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL] = 0xff00000000000000; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("entry msr load addr too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL] = 0xfffffff0; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("end of entry msr load area too large"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL] = 0x10; };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
vmcs_ut::test_check_control_pin_based_ctls_reserved_properly_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_pin_based_ctls_reserved_properly_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_pin_based_ctls_reserved_properly_set);
}

void
vmcs_ut::test_check_control_proc_based_ctls_reserved_properly_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_proc_based_ctls_reserved_properly_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_proc_based_ctls_reserved_properly_set);
}

void
vmcs_ut::test_check_control_proc_based_ctls2_reserved_properly_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_proc_based_ctls2_reserved_properly_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_proc_based_ctls2_reserved_properly_set);
}

void
vmcs_ut::test_check_control_cr3_count_less_than_4()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_cr3_count_less_than_4_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_cr3_count_less_then_4);
}

void
vmcs_ut::test_check_control_io_bitmap_address_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_io_bitmap_address_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_io_bitmap_address_bits);
}

void
vmcs_ut::test_check_control_msr_bitmap_address_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_msr_bitmap_address_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_msr_bitmap_address_bits);
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_tpr_shadow_and_virtual_apic_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_tpr_shadow_and_virtual_apic);
}

void
vmcs_ut::test_check_control_nmi_exiting_and_virtual_nmi()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_nmi_exiting_and_virtual_nmi_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_nmi_exiting_and_virtual_nmi);
}

void
vmcs_ut::test_check_control_virtual_nmi_and_nmi_window()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_virtual_nmi_and_nmi_window_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_virtual_nmi_and_nmi_window);
}

void
vmcs_ut::test_check_control_virtual_apic_address_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_virtual_apic_address_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_virtual_apic_address_bits);
}

void
vmcs_ut::test_check_control_x2apic_mode_and_virtual_apic_access()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_x2apic_mode_and_virtual_apic_access_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_x2apic_mode_and_virtual_apic_access);
}

void
vmcs_ut::test_check_control_virtual_interrupt_and_external_interrupt()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_virtual_interrupt_and_external_interrupt_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_virtual_interrupt_and_external_interrupt);
}

void
vmcs_ut::test_check_control_process_posted_interrupt_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_process_posted_interrupt_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_process_posted_interrupt_checks);
}

void
vmcs_ut::test_check_control_vpid_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vpid_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_vpid_checks);
}

void
vmcs_ut::test_check_control_enable_ept_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_ept_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_enable_ept_checks);
}

void
vmcs_ut::test_check_control_enable_pml_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_pml_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_enable_pml_checks);
}

void
vmcs_ut::test_check_control_unrestricted_guests()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_unrestricted_guests_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_unrestricted_guests);
}

void
vmcs_ut::test_check_control_enable_vm_functions()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_vm_functions_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_enable_vm_functions);
}

void
vmcs_ut::test_check_control_enable_vmcs_shadowing()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_vmcs_shadowing_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_enable_vmcs_shadowing);
}

void
vmcs_ut::test_check_control_enable_ept_violation_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_ept_violation_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_enable_ept_violation_checks);
}

void
vmcs_ut::test_check_control_vm_exit_ctls_reserved_properly_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vm_exit_ctls_reserved_properly_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_vm_exit_ctls_reserved_properly_set);
}

void
vmcs_ut::test_check_control_activate_and_save_preemption_timer_must_be_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_activate_and_save_preemption_timer_must_be_0_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_activate_and_save_preemption_timer_must_be_0);
}

void
vmcs_ut::test_check_control_exit_msr_store_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_exit_msr_store_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_exit_msr_store_address);
}

void
vmcs_ut::test_check_control_exit_msr_load_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_exit_msr_load_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_exit_msr_load_address);
}

void
vmcs_ut::test_check_control_vm_entry_ctls_reserved_properly_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vm_entry_ctls_reserved_properly_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_vm_entry_ctls_reserved_properly_set);
}

void
vmcs_ut::test_check_control_event_injection_type_vector_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_type_vector_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_event_injection_type_vector_checks);
}

void
vmcs_ut::test_check_control_event_injection_delivery_ec_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_delivery_ec_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_event_injection_delivery_ec_checks);
}

void
vmcs_ut::test_check_control_event_injection_reserved_bits_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_reserved_bits_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_event_injection_reserved_bits_checks);
}

void
vmcs_ut::test_check_control_event_injection_ec_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_ec_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_event_injection_ec_checks);
}

void
vmcs_ut::test_check_control_event_injection_instr_length_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_instr_length_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_event_injection_instr_length_checks);
}

void
vmcs_ut::test_check_control_entry_msr_load_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_entry_msr_load_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_entry_msr_load_address);
}
