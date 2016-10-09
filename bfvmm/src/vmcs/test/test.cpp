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

#include <test.h>
#include <new_delete.h>

using namespace intel_x64;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;
uint8_t span[0x81] = {0};
bool g_vmread_fails = false;
bool g_vmwrite_fails = false;
bool g_virt_to_phys_return_nullptr = false;
bool g_phys_to_virt_return_nullptr = false;

void
setup_mock(MockRepository &mocks, memory_manager *mm, intrinsics_intel_x64 *in)
{
    mocks.OnCall(in, intrinsics_intel_x64::vmread).Do(__vmread);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).Do(__read_msr);
    mocks.OnCall(in, intrinsics_intel_x64::cpuid_eax).With(0x80000008).Return(32);
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::physint_to_virtptr).Do(physint_to_virtptr);
}

void
enable_proc_ctl(uint64_t control)
{
    g_vmcs_fields[VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS] |= control;
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= control << 32;
}

void
enable_proc_ctl2(uint64_t control)
{
    enable_proc_ctl(VM_EXEC_P_PROC_BASED_ACTIVATE_SECONDARY_CONTROLS);
    g_vmcs_fields[VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS] |= control;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= control << 32;
}

void
enable_pin_ctl(uint64_t control)
{
    g_vmcs_fields[VMCS_PIN_BASED_VM_EXECUTION_CONTROLS] |= control;
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] |= control << 32;
}

void
disable_proc_ctl(uint64_t control)
{
    g_vmcs_fields[VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS] &= ~control;
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] &= ~control;
}

void
disable_proc_ctl2(uint64_t control)
{
    g_vmcs_fields[VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS] &= ~control;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] &= ~control;
}

void
disable_pin_ctl(uint64_t control)
{
    g_vmcs_fields[VMCS_PIN_BASED_VM_EXECUTION_CONTROLS] &= ~control;
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] &= ~control;
}

void
disable_exit_ctl(uint64_t control)
{
    g_vmcs_fields[VMCS_VM_EXIT_CONTROLS] &= ~control;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] &= ~control;
}

void
enable_exit_ctl(uint64_t control)
{
    g_vmcs_fields[VMCS_VM_EXIT_CONTROLS] |= control;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= control << 32;
}

void
disable_entry_ctl(uint64_t control)
{
    g_vmcs_fields[VMCS_VM_ENTRY_CONTROLS] &= ~control;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] &= ~control;
}

void
enable_entry_ctl(uint64_t control)
{
    g_vmcs_fields[VMCS_VM_ENTRY_CONTROLS] |= control;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= control << 32;
}

extern "C" uint64_t
__read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

bool
__vmread(uint64_t field, uint64_t *val) noexcept
{
    if (g_vmread_fails)
        return false;

    *val = g_vmcs_fields[field];
    return true;
}

bool
__vmwrite(uint64_t field, uint64_t val) noexcept
{
    if (g_vmwrite_fails)
        return false;

    g_vmcs_fields[field] = val;
    return true;
}

uint32_t
cpuid_eax(uint32_t val)
{
    switch (val)
    {
        default:
            return 0xff;
    }
}

uintptr_t
virtptr_to_physint(void *ptr)
{
    (void) ptr;

    if (g_virt_to_phys_return_nullptr)
        return 0;

    return 0x0000000ABCDEF0000;
}

void *
physint_to_virtptr(uintptr_t phys)
{
    (void) phys;

    if (g_phys_to_virt_return_nullptr)
        return nullptr;

    return static_cast<void *>(&span);
}

vmcs_ut::vmcs_ut()
{
}

bool
vmcs_ut::init()
{
    return true;
}

bool
vmcs_ut::fini()
{
    return true;
}

bool
vmcs_ut::list()
{
    this->test_constructor_null_intrinsics();
    this->test_launch_success();
    this->test_launch_vmlaunch_failure();
    this->test_launch_create_vmcs_region_failure();
    this->test_launch_create_exit_handler_stack_failure();
    this->test_launch_clear_failure();
    this->test_launch_load_failure();
    this->test_promote_failure();
    this->test_resume_failure();
    this->test_vmread_failure();
    this->test_vmwrite_failure();
    this->test_vmcs_virtual_processor_identifier();
    this->test_vmcs_posted_interrupt_notification_vector();
    this->test_vmcs_eptp_index();
    this->test_vmcs_guest_es_selector();
    this->test_vmcs_guest_cs_selector();
    this->test_vmcs_guest_ss_selector();
    this->test_vmcs_guest_ds_selector();
    this->test_vmcs_guest_fs_selector();
    this->test_vmcs_guest_gs_selector();
    this->test_vmcs_guest_ldtr_selector();
    this->test_vmcs_guest_tr_selector();
    this->test_vmcs_guest_interrupt_status();
    this->test_vmcs_host_es_selector();
    this->test_vmcs_host_cs_selector();
    this->test_vmcs_host_ss_selector();
    this->test_vmcs_host_ds_selector();
    this->test_vmcs_host_fs_selector();
    this->test_vmcs_host_gs_selector();
    this->test_vmcs_host_tr_selector();
    this->test_vmcs_guest_rflags();
    this->test_vmcs_guest_rflags_carry_flag();
    this->test_vmcs_guest_rflags_parity_flag();
    this->test_vmcs_guest_rflags_auxiliary_carry_flag();
    this->test_vmcs_guest_rflags_zero_flag();
    this->test_vmcs_guest_rflags_sign_flag();
    this->test_vmcs_guest_rflags_trap_flag();
    this->test_vmcs_guest_rflags_interrupt_enable_flag();
    this->test_vmcs_guest_rflags_direction_flag();
    this->test_vmcs_guest_rflags_overflow_flag();
    this->test_vmcs_guest_rflags_privilege_level();
    this->test_vmcs_guest_rflags_nested_task();
    this->test_vmcs_guest_rflags_resume_flag();
    this->test_vmcs_guest_rflags_virtual_8086_mode();
    this->test_vmcs_guest_rflags_alignment_check_access_control();
    this->test_vmcs_guest_rflags_virtual_interupt_flag();
    this->test_vmcs_guest_rflags_virtual_interupt_pending();
    this->test_vmcs_guest_rflags_id_flag();
    this->test_vmcs_guest_rflags_reserved();
    this->test_vmcs_guest_rflags_always_disabled();
    this->test_vmcs_guest_rflags_always_enabled();
    this->test_vmcs_guest_cr0();
    this->test_vmcs_guest_cr0_protection_enable();
    this->test_vmcs_guest_cr0_monitor_coprocessor();
    this->test_vmcs_guest_cr0_emulation();
    this->test_vmcs_guest_cr0_task_switched();
    this->test_vmcs_guest_cr0_extension_type();
    this->test_vmcs_guest_cr0_numeric_error();
    this->test_vmcs_guest_cr0_write_protect();
    this->test_vmcs_guest_cr0_alignment_mask();
    this->test_vmcs_guest_cr0_not_write_through();
    this->test_vmcs_guest_cr0_cache_disable();
    this->test_vmcs_guest_cr0_paging();
    this->test_vmcs_guest_cr3();
    this->test_vmcs_guest_cr4();
    this->test_vmcs_guest_cr4_v8086_mode_extensions();
    this->test_vmcs_guest_cr4_protected_mode_virtual_interrupts();
    this->test_vmcs_guest_cr4_time_stamp_disable();
    this->test_vmcs_guest_cr4_debugging_extensions();
    this->test_vmcs_guest_cr4_page_size_extensions();
    this->test_vmcs_guest_cr4_physical_address_extensions();
    this->test_vmcs_guest_cr4_machine_check_enable();
    this->test_vmcs_guest_cr4_page_global_enable();
    this->test_vmcs_guest_cr4_performance_monitor_counter_enable();
    this->test_vmcs_guest_cr4_osfxsr();
    this->test_vmcs_guest_cr4_osxmmexcpt();
    this->test_vmcs_guest_cr4_vmx_enable_bit();
    this->test_vmcs_guest_cr4_smx_enable_bit();
    this->test_vmcs_guest_cr4_fsgsbase_enable_bit();
    this->test_vmcs_guest_cr4_pcid_enable_bit();
    this->test_vmcs_guest_cr4_osxsave();
    this->test_vmcs_guest_cr4_smep_enable_bit();
    this->test_vmcs_guest_cr4_smap_enable_bit();
    this->test_vmcs_guest_cr4_protection_key_enable_bit();
    this->test_vmcs_host_cr0();
    this->test_vmcs_host_cr0_protection_enable();
    this->test_vmcs_host_cr0_monitor_coprocessor();
    this->test_vmcs_host_cr0_emulation();
    this->test_vmcs_host_cr0_task_switched();
    this->test_vmcs_host_cr0_extension_type();
    this->test_vmcs_host_cr0_numeric_error();
    this->test_vmcs_host_cr0_write_protect();
    this->test_vmcs_host_cr0_alignment_mask();
    this->test_vmcs_host_cr0_not_write_through();
    this->test_vmcs_host_cr0_cache_disable();
    this->test_vmcs_host_cr0_paging();
    this->test_vmcs_host_cr3();
    this->test_vmcs_host_cr4();
    this->test_vmcs_host_cr4_v8086_mode_extensions();
    this->test_vmcs_host_cr4_protected_mode_virtual_interrupts();
    this->test_vmcs_host_cr4_time_stamp_disable();
    this->test_vmcs_host_cr4_debugging_extensions();
    this->test_vmcs_host_cr4_page_size_extensions();
    this->test_vmcs_host_cr4_physical_address_extensions();
    this->test_vmcs_host_cr4_machine_check_enable();
    this->test_vmcs_host_cr4_page_global_enable();
    this->test_vmcs_host_cr4_performance_monitor_counter_enable();
    this->test_vmcs_host_cr4_osfxsr();
    this->test_vmcs_host_cr4_osxmmexcpt();
    this->test_vmcs_host_cr4_vmx_enable_bit();
    this->test_vmcs_host_cr4_smx_enable_bit();
    this->test_vmcs_host_cr4_fsgsbase_enable_bit();
    this->test_vmcs_host_cr4_pcid_enable_bit();
    this->test_vmcs_host_cr4_osxsave();
    this->test_vmcs_host_cr4_smep_enable_bit();
    this->test_vmcs_host_cr4_smap_enable_bit();
    this->test_vmcs_host_cr4_protection_key_enable_bit();
    this->test_vmcs_guest_ia32_debugctl();
    this->test_vmcs_guest_ia32_debugctl_lbr();
    this->test_vmcs_guest_ia32_debugctl_btf();
    this->test_vmcs_guest_ia32_debugctl_tr();
    this->test_vmcs_guest_ia32_debugctl_bts();
    this->test_vmcs_guest_ia32_debugctl_btint();
    this->test_vmcs_guest_ia32_debugctl_bt_off_os();
    this->test_vmcs_guest_ia32_debugctl_bt_off_user();
    this->test_vmcs_guest_ia32_debugctl_freeze_lbrs_on_pmi();
    this->test_vmcs_guest_ia32_debugctl_freeze_perfmon_on_pmi();
    this->test_vmcs_guest_ia32_debugctl_enable_uncore_pmi();
    this->test_vmcs_guest_ia32_debugctl_freeze_while_smm();
    this->test_vmcs_guest_ia32_debugctl_rtm_debug();
    this->test_vmcs_guest_ia32_debugctl_reserved();
    this->test_vmcs_guest_ia32_efer();
    this->test_vmcs_guest_ia32_efer_sce();
    this->test_vmcs_guest_ia32_efer_lme();
    this->test_vmcs_guest_ia32_efer_lma();
    this->test_vmcs_guest_ia32_efer_nxe();
    this->test_vmcs_guest_ia32_efer_reserved();
    this->test_vmcs_host_ia32_efer();
    this->test_vmcs_host_ia32_efer_sce();
    this->test_vmcs_host_ia32_efer_lme();
    this->test_vmcs_host_ia32_efer_lma();
    this->test_vmcs_host_ia32_efer_nxe();
    this->test_vmcs_host_ia32_efer_reserved();

    this->test_check_control_pin_based_ctls_reserved_properly_set();
    this->test_check_control_proc_based_ctls_reserved_properly_set();
    this->test_check_control_proc_based_ctls2_reserved_properly_set();
    this->test_check_control_cr3_count_less_than_4();
    this->test_check_control_io_bitmap_address_bits();
    this->test_check_control_msr_bitmap_address_bits();
    this->test_check_control_tpr_shadow_and_virtual_apic();
    this->test_check_control_nmi_exiting_and_virtual_nmi();
    this->test_check_control_virtual_nmi_and_nmi_window();
    this->test_check_control_virtual_apic_address_bits();
    this->test_check_control_x2apic_mode_and_virtual_apic_access();
    this->test_check_control_virtual_interrupt_and_external_interrupt();
    this->test_check_control_process_posted_interrupt_checks();
    this->test_check_control_vpid_checks();
    this->test_check_control_enable_ept_checks();
    this->test_check_control_enable_pml_checks();
    this->test_check_control_unrestricted_guests();
    this->test_check_control_enable_vm_functions();
    this->test_check_control_enable_vmcs_shadowing();
    this->test_check_control_enable_ept_violation_checks();
    this->test_check_control_vm_exit_ctls_reserved_properly_set();
    this->test_check_control_activate_and_save_preemption_timer_must_be_0();
    this->test_check_control_exit_msr_store_address();
    this->test_check_control_exit_msr_load_address();
    this->test_check_control_vm_entry_ctls_reserved_properly_set();
    this->test_check_control_event_injection_type_vector_checks();
    this->test_check_control_event_injection_delivery_ec_checks();
    this->test_check_control_event_injection_reserved_bits_checks();
    this->test_check_control_event_injection_ec_checks();
    this->test_check_control_event_injection_instr_length_checks();
    this->test_check_control_entry_msr_load_address();

    this->test_check_host_cr0_for_unsupported_bits();
    this->test_check_host_cr4_for_unsupported_bits();
    this->test_check_host_cr3_for_unsupported_bits();
    this->test_check_host_ia32_sysenter_esp_canonical_address();
    this->test_check_host_ia32_sysenter_eip_canonical_address();
    this->test_check_host_verify_load_ia32_perf_global_ctrl();
    this->test_check_host_verify_load_ia32_pat();
    this->test_check_host_verify_load_ia32_efer();
    this->test_check_host_es_selector_rpl_ti_equal_zero();
    this->test_check_host_cs_selector_rpl_ti_equal_zero();
    this->test_check_host_ss_selector_rpl_ti_equal_zero();
    this->test_check_host_ds_selector_rpl_ti_equal_zero();
    this->test_check_host_fs_selector_rpl_ti_equal_zero();
    this->test_check_host_gs_selector_rpl_ti_equal_zero();
    this->test_check_host_tr_selector_rpl_ti_equal_zero();
    this->test_check_host_cs_not_equal_zero();
    this->test_check_host_tr_not_equal_zero();
    this->test_check_host_ss_not_equal_zero();
    this->test_check_host_fs_canonical_base_address();
    this->test_check_host_gs_canonical_base_address();
    this->test_check_host_gdtr_canonical_base_address();
    this->test_check_host_idtr_canonical_base_address();
    this->test_check_host_tr_canonical_base_address();
    this->test_check_host_if_outside_ia32e_mode();
    this->test_check_host_vmcs_host_address_space_size_is_set();
    this->test_check_host_host_address_space_disabled();
    this->test_check_host_host_address_space_enabled();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(vmcs_ut);
}
