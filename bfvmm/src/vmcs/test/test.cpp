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
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <test.h>
#include <new_delete.h>

#include <intrinsics/cpuid_x64.h>

using namespace x64;
using namespace intel_x64;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;
std::map<uint32_t, uint32_t> g_eax_cpuid;

struct cpuid_regs g_cpuid_regs;

bool g_vmclear_fails = false;
bool g_vmload_fails = false;
bool g_vmlaunch_fails = false;
bool g_virt_to_phys_return_nullptr = false;
bool g_phys_to_virt_return_nullptr = false;

uint64_t g_test_addr = 0U;
uint64_t g_virt_apic_addr = 0U;
uint8_t g_virt_apic_mem[0x81] = {0U};

uint64_t g_vmcs_link_addr = 1U;
uint32_t g_vmcs_link_mem[1] = {0U};

uint64_t g_pdpt_addr = 2U;
uint64_t g_pdpt_mem[4] = {0U};

std::map<uint64_t, void *> g_mock_mem
{
    {
        {g_virt_apic_addr, static_cast<void *>(&g_virt_apic_mem)},
        {g_vmcs_link_addr, static_cast<void *>(&g_vmcs_link_mem)},
        {g_pdpt_addr, static_cast<void *>(&g_pdpt_mem)}
    }
};

void
setup_mock(MockRepository &mocks, memory_manager_x64 *mm)
{
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::physint_to_virtptr).Do(physint_to_virtptr);
}

void
proc_ctl_allow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= mask << 32; }

void
proc_ctl_allow0(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] &= ~mask; }

void
proc_ctl_disallow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] &= ~(mask << 32); }

void
proc_ctl2_allow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= mask << 32; }

void
proc_ctl2_allow0(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] &= ~mask; }

void
proc_ctl2_disallow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] &= ~(mask << 32); }

void
pin_ctl_allow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] |= mask << 32; }

void
pin_ctl_allow0(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] &= ~mask; }

void
exit_ctl_allow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= mask << 32; }

void
exit_ctl_allow0(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] &= ~mask; }

void
entry_ctl_allow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= mask << 32; }

void
entry_ctl_allow0(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] &= ~mask; }

void
vmfunc_ctl_allow1(uint64_t mask)
{ g_msrs[msrs::ia32_vmx_vmfunc::addr] |= mask; }

extern "C" uint64_t
__read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
__write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

extern "C" uint32_t
__cpuid_eax(uint32_t val) noexcept
{ return g_eax_cpuid[val]; }


extern "C" void
__cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept
{
    *static_cast<uint32_t *>(eax) = g_cpuid_regs.eax;
    *static_cast<uint32_t *>(ebx) = g_cpuid_regs.ebx;
    *static_cast<uint32_t *>(ecx) = g_cpuid_regs.ecx;
    *static_cast<uint32_t *>(edx) = g_cpuid_regs.edx;
}

bool
__vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs_fields[field];
    return true;
}

bool
__vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs_fields[field] = val;
    return true;
}

extern "C" bool
__vmclear(void *ptr) noexcept
{ (void)ptr; return !g_vmclear_fails; }

extern "C" bool
__vmptrld(void *ptr) noexcept
{ (void)ptr; return !g_vmload_fails; }

extern "C" bool
__vmlaunch(void) noexcept
{ return !g_vmlaunch_fails; }

uintptr_t
virtptr_to_physint(void *ptr)
{
    (void) ptr;

    if (g_virt_to_phys_return_nullptr)
        throw gsl::fail_fast("");

    return 0x0000000ABCDEF0000;
}

void *
physint_to_virtptr(uintptr_t phys)
{
    (void) phys;

    if (g_phys_to_virt_return_nullptr)
        return nullptr;

    return static_cast<void *>(g_mock_mem[g_test_addr]);
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

void
vmcs_ut::list_vmcs_intel_x64_cpp()
{
    this->test_launch_success();
    this->test_launch_vmlaunch_failure();
    this->test_launch_create_vmcs_region_failure();
    this->test_launch_create_exit_handler_stack_failure();
    this->test_launch_clear_failure();
    this->test_launch_load_failure();
    this->test_promote_failure();
    this->test_resume_failure();
}

void
vmcs_ut::list_vmcs_intel_x64_h()
{
    this->test_get_vmcs_field();
    this->test_get_vmcs_field_if_exists();
    this->test_set_vmcs_field();
    this->test_set_vmcs_field_if_exists();
    this->test_set_vm_control();
    this->test_set_vm_control_if_allowed();
    this->test_set_vm_function_control();
    this->test_set_vm_function_control_if_allowed();
}

void
vmcs_ut::list_16bit_control_fields()
{
    this->test_vmcs_virtual_processor_identifier();
    this->test_vmcs_posted_interrupt_notification_vector();
    this->test_vmcs_eptp_index();
}

void
vmcs_ut::list_16bit_guest_state_fields()
{
    this->test_vmcs_guest_es_selector();
    this->test_vmcs_guest_es_selector_rpl();
    this->test_vmcs_guest_es_selector_ti();
    this->test_vmcs_guest_es_selector_index();
    this->test_vmcs_guest_cs_selector();
    this->test_vmcs_guest_cs_selector_rpl();
    this->test_vmcs_guest_cs_selector_ti();
    this->test_vmcs_guest_cs_selector_index();
    this->test_vmcs_guest_ss_selector();
    this->test_vmcs_guest_ss_selector_rpl();
    this->test_vmcs_guest_ss_selector_ti();
    this->test_vmcs_guest_ss_selector_index();
    this->test_vmcs_guest_ds_selector();
    this->test_vmcs_guest_ds_selector_rpl();
    this->test_vmcs_guest_ds_selector_ti();
    this->test_vmcs_guest_ds_selector_index();
    this->test_vmcs_guest_fs_selector();
    this->test_vmcs_guest_fs_selector_rpl();
    this->test_vmcs_guest_fs_selector_ti();
    this->test_vmcs_guest_fs_selector_index();
    this->test_vmcs_guest_gs_selector();
    this->test_vmcs_guest_gs_selector_rpl();
    this->test_vmcs_guest_gs_selector_ti();
    this->test_vmcs_guest_gs_selector_index();
    this->test_vmcs_guest_ldtr_selector();
    this->test_vmcs_guest_ldtr_selector_rpl();
    this->test_vmcs_guest_ldtr_selector_ti();
    this->test_vmcs_guest_ldtr_selector_index();
    this->test_vmcs_guest_tr_selector();
    this->test_vmcs_guest_tr_selector_rpl();
    this->test_vmcs_guest_tr_selector_ti();
    this->test_vmcs_guest_tr_selector_index();
    this->test_vmcs_guest_interrupt_status();
}

void
vmcs_ut::list_16bit_host_state_fields()
{
    this->test_vmcs_host_es_selector();
    this->test_vmcs_host_es_selector_rpl();
    this->test_vmcs_host_es_selector_ti();
    this->test_vmcs_host_es_selector_index();
    this->test_vmcs_host_cs_selector();
    this->test_vmcs_host_cs_selector_rpl();
    this->test_vmcs_host_cs_selector_ti();
    this->test_vmcs_host_cs_selector_index();
    this->test_vmcs_host_ss_selector();
    this->test_vmcs_host_ss_selector_rpl();
    this->test_vmcs_host_ss_selector_ti();
    this->test_vmcs_host_ss_selector_index();
    this->test_vmcs_host_ds_selector();
    this->test_vmcs_host_ds_selector_rpl();
    this->test_vmcs_host_ds_selector_ti();
    this->test_vmcs_host_ds_selector_index();
    this->test_vmcs_host_fs_selector();
    this->test_vmcs_host_fs_selector_rpl();
    this->test_vmcs_host_fs_selector_ti();
    this->test_vmcs_host_fs_selector_index();
    this->test_vmcs_host_gs_selector();
    this->test_vmcs_host_gs_selector_rpl();
    this->test_vmcs_host_gs_selector_ti();
    this->test_vmcs_host_gs_selector_index();
    this->test_vmcs_host_tr_selector();
    this->test_vmcs_host_tr_selector_rpl();
    this->test_vmcs_host_tr_selector_ti();
    this->test_vmcs_host_tr_selector_index();
}

void
vmcs_ut::list_64bit_control_fields()
{
    this->test_vmcs_address_of_io_bitmap_a();
    this->test_vmcs_address_of_io_bitmap_b();
    this->test_vmcs_address_of_msr_bitmaps();
    this->test_vmcs_vm_exit_msr_store_address();
    this->test_vmcs_vm_exit_msr_load_address();
    this->test_vmcs_vm_entry_msr_load_address();
    this->test_vmcs_executive_vmcs_pointer();
    this->test_vmcs_pml_address();
    this->test_vmcs_tsc_offset();
    this->test_vmcs_virtual_apic_address();
    this->test_vmcs_apic_access_address();
    this->test_vmcs_posted_interrupt_descriptor_address();
    this->test_vmcs_vm_function_controls();
    this->test_vmcs_vm_function_controls_eptp_switching();
    this->test_vmcs_vm_function_controls_reserved();
    this->test_vmcs_ept_pointer();
    this->test_vmcs_ept_pointer_memory_type();
    this->test_vmcs_ept_pointer_page_walk_length_minus_one();
    this->test_vmcs_ept_pointer_accessed_and_dirty_flags();
    this->test_vmcs_ept_pointer_reserved();
    this->test_vmcs_eoi_exit_bitmap_0();
    this->test_vmcs_eoi_exit_bitmap_1();
    this->test_vmcs_eoi_exit_bitmap_2();
    this->test_vmcs_eoi_exit_bitmap_3();
    this->test_vmcs_eptp_list_address();
    this->test_vmcs_vmread_bitmap_address();
    this->test_vmcs_vmwrite_bitmap_address();
    this->test_vmcs_virtualization_exception_information_address();
    this->test_vmcs_xss_exiting_bitmap();
}

void
vmcs_ut::list_64bit_read_only_data_field()
{
    this->test_vmcs_guest_physical_address();
}

void
vmcs_ut::list_64bit_guest_state_fields()
{
    this->test_vmcs_vmcs_link_pointer();
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
    this->test_vmcs_guest_ia32_pat();
    this->test_vmcs_guest_ia32_pat_pa0();
    this->test_vmcs_guest_ia32_pat_pa0_memory_type();
    this->test_vmcs_guest_ia32_pat_pa0_reserved();
    this->test_vmcs_guest_ia32_pat_pa1();
    this->test_vmcs_guest_ia32_pat_pa1_memory_type();
    this->test_vmcs_guest_ia32_pat_pa1_reserved();
    this->test_vmcs_guest_ia32_pat_pa2();
    this->test_vmcs_guest_ia32_pat_pa2_memory_type();
    this->test_vmcs_guest_ia32_pat_pa2_reserved();
    this->test_vmcs_guest_ia32_pat_pa3();
    this->test_vmcs_guest_ia32_pat_pa3_memory_type();
    this->test_vmcs_guest_ia32_pat_pa3_reserved();
    this->test_vmcs_guest_ia32_pat_pa4();
    this->test_vmcs_guest_ia32_pat_pa4_memory_type();
    this->test_vmcs_guest_ia32_pat_pa4_reserved();
    this->test_vmcs_guest_ia32_pat_pa5();
    this->test_vmcs_guest_ia32_pat_pa5_memory_type();
    this->test_vmcs_guest_ia32_pat_pa5_reserved();
    this->test_vmcs_guest_ia32_pat_pa6();
    this->test_vmcs_guest_ia32_pat_pa6_memory_type();
    this->test_vmcs_guest_ia32_pat_pa6_reserved();
    this->test_vmcs_guest_ia32_pat_pa7();
    this->test_vmcs_guest_ia32_pat_pa7_memory_type();
    this->test_vmcs_guest_ia32_pat_pa7_reserved();
    this->test_vmcs_guest_ia32_efer();
    this->test_vmcs_guest_ia32_efer_sce();
    this->test_vmcs_guest_ia32_efer_lme();
    this->test_vmcs_guest_ia32_efer_lma();
    this->test_vmcs_guest_ia32_efer_nxe();
    this->test_vmcs_guest_ia32_efer_reserved();
    this->test_vmcs_guest_ia32_perf_global_ctrl();
    this->test_vmcs_guest_ia32_perf_global_ctrl_reserved();
    this->test_vmcs_guest_pdpte0();
    this->test_vmcs_guest_pdpte0_present();
    this->test_vmcs_guest_pdpte0_reserved();
    this->test_vmcs_guest_pdpte0_pwt();
    this->test_vmcs_guest_pdpte0_pcd();
    this->test_vmcs_guest_pdpte0_page_directory_addr();
    this->test_vmcs_guest_pdpte1();
    this->test_vmcs_guest_pdpte1_present();
    this->test_vmcs_guest_pdpte1_reserved();
    this->test_vmcs_guest_pdpte1_pwt();
    this->test_vmcs_guest_pdpte1_pcd();
    this->test_vmcs_guest_pdpte1_page_directory_addr();
    this->test_vmcs_guest_pdpte2();
    this->test_vmcs_guest_pdpte2_present();
    this->test_vmcs_guest_pdpte2_reserved();
    this->test_vmcs_guest_pdpte2_pwt();
    this->test_vmcs_guest_pdpte2_pcd();
    this->test_vmcs_guest_pdpte2_page_directory_addr();
    this->test_vmcs_guest_pdpte3();
    this->test_vmcs_guest_pdpte3_present();
    this->test_vmcs_guest_pdpte3_reserved();
    this->test_vmcs_guest_pdpte3_pwt();
    this->test_vmcs_guest_pdpte3_pcd();
    this->test_vmcs_guest_pdpte3_page_directory_addr();
    this->test_vmcs_guest_ia32_bndcfgs();
    this->test_vmcs_guest_ia32_bndcfgs_en();
    this->test_vmcs_guest_ia32_bndcfgs_bndpreserve();
    this->test_vmcs_guest_ia32_bndcfgs_reserved();
    this->test_vmcs_guest_ia32_bndcfgs_base_addr_of_bnd_directory();
}

void
vmcs_ut::list_64bit_host_state_fields()
{
    this->test_vmcs_host_ia32_pat();
    this->test_vmcs_host_ia32_pat_pa0();
    this->test_vmcs_host_ia32_pat_pa0_memory_type();
    this->test_vmcs_host_ia32_pat_pa0_reserved();
    this->test_vmcs_host_ia32_pat_pa1();
    this->test_vmcs_host_ia32_pat_pa1_memory_type();
    this->test_vmcs_host_ia32_pat_pa1_reserved();
    this->test_vmcs_host_ia32_pat_pa2();
    this->test_vmcs_host_ia32_pat_pa2_memory_type();
    this->test_vmcs_host_ia32_pat_pa2_reserved();
    this->test_vmcs_host_ia32_pat_pa3();
    this->test_vmcs_host_ia32_pat_pa3_memory_type();
    this->test_vmcs_host_ia32_pat_pa3_reserved();
    this->test_vmcs_host_ia32_pat_pa4();
    this->test_vmcs_host_ia32_pat_pa4_memory_type();
    this->test_vmcs_host_ia32_pat_pa4_reserved();
    this->test_vmcs_host_ia32_pat_pa5();
    this->test_vmcs_host_ia32_pat_pa5_memory_type();
    this->test_vmcs_host_ia32_pat_pa5_reserved();
    this->test_vmcs_host_ia32_pat_pa6();
    this->test_vmcs_host_ia32_pat_pa6_memory_type();
    this->test_vmcs_host_ia32_pat_pa6_reserved();
    this->test_vmcs_host_ia32_pat_pa7();
    this->test_vmcs_host_ia32_pat_pa7_memory_type();
    this->test_vmcs_host_ia32_pat_pa7_reserved();
    this->test_vmcs_host_ia32_efer();
    this->test_vmcs_host_ia32_efer_sce();
    this->test_vmcs_host_ia32_efer_lme();
    this->test_vmcs_host_ia32_efer_lma();
    this->test_vmcs_host_ia32_efer_nxe();
    this->test_vmcs_host_ia32_efer_reserved();
    this->test_vmcs_host_ia32_perf_global_ctrl();
    this->test_vmcs_host_ia32_perf_global_ctrl_reserved();
}

void
vmcs_ut::list_32bit_control_fields()
{
    this->test_vmcs_pin_based_vm_execution_controls();
    this->test_vmcs_pin_based_vm_execution_controls_external_interrupt_exiting();
    this->test_vmcs_pin_based_vm_execution_controls_nmi_exiting();
    this->test_vmcs_pin_based_vm_execution_controls_virtual_nmis();
    this->test_vmcs_pin_based_vm_execution_controls_activate_vmx_preemption_timer();
    this->test_vmcs_pin_based_vm_execution_controls_process_posted_interrupts();
    this->test_vmcs_primary_processor_based_vm_execution_controls();
    this->test_vmcs_primary_processor_based_vm_execution_controls_interrupt_window_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_use_tsc_offsetting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_hlt_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_invlpg_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_mwait_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_rdpmc_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_rdtsc_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_cr3_load_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_cr3_store_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_cr8_load_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_cr8_store_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_use_tpr_shadow();
    this->test_vmcs_primary_processor_based_vm_execution_controls_mov_dr_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_unconditional_io_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_nmi_window_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_use_io_bitmaps();
    this->test_vmcs_primary_processor_based_vm_execution_controls_monitor_trap_flag();
    this->test_vmcs_primary_processor_based_vm_execution_controls_use_msr_bitmaps();
    this->test_vmcs_primary_processor_based_vm_execution_controls_monitor_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_pause_exiting();
    this->test_vmcs_primary_processor_based_vm_execution_controls_activate_secondary_controls();
    this->test_vmcs_exception_bitmap();
    this->test_vmcs_page_fault_error_code_mask();
    this->test_vmcs_page_fault_error_code_match();
    this->test_vmcs_cr3_target_count();
    this->test_vmcs_vm_exit_controls();
    this->test_vmcs_vm_exit_controls_save_debug_controls();
    this->test_vmcs_vm_exit_controls_host_address_space_size();
    this->test_vmcs_vm_exit_controls_load_ia32_perf_global_ctrl();
    this->test_vmcs_vm_exit_controls_acknowledge_interrupt_on_exit();
    this->test_vmcs_vm_exit_controls_save_ia32_pat();
    this->test_vmcs_vm_exit_controls_load_ia32_pat();
    this->test_vmcs_vm_exit_controls_save_ia32_efer();
    this->test_vmcs_vm_exit_controls_load_ia32_efer();
    this->test_vmcs_vm_exit_controls_save_vmx_preemption_timer_value();
    this->test_vmcs_vm_exit_controls_clear_ia32_bndcfgs();
    this->test_vmcs_vm_exit_msr_store_count();
    this->test_vmcs_vm_exit_msr_load_count();
    this->test_vmcs_vm_entry_controls();
    this->test_vmcs_vm_entry_controls_load_debug_controls();
    this->test_vmcs_vm_entry_controls_ia_32e_mode_guest();
    this->test_vmcs_vm_entry_controls_entry_to_smm();
    this->test_vmcs_vm_entry_controls_deactivate_dual_monitor_treatment();
    this->test_vmcs_vm_entry_controls_load_ia32_perf_global_ctrl();
    this->test_vmcs_vm_entry_controls_load_ia32_pat();
    this->test_vmcs_vm_entry_controls_load_ia32_efer();
    this->test_vmcs_vm_entry_controls_load_ia32_bndcfgs();
    this->test_vmcs_vm_entry_msr_load_count();
    this->test_vmcs_vm_entry_interruption_information_field();
    this->test_vmcs_vm_entry_interruption_information_field_vector();
    this->test_vmcs_vm_entry_interruption_information_field_type();
    this->test_vmcs_vm_entry_interruption_information_field_deliver_error_code_bit();
    this->test_vmcs_vm_entry_interruption_information_field_reserved();
    this->test_vmcs_vm_entry_interruption_information_field_valid_bit();
    this->test_vmcs_vm_entry_exception_error_code();
    this->test_vmcs_vm_entry_instruction_length();
    this->test_vmcs_tpr_threshold();
    this->test_vmcs_secondary_processor_based_vm_execution_controls();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_virtualize_apic_accesses();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_enable_ept();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_descriptor_table_exiting();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_enable_rdtscp();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_virtualize_x2apic_mode();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_enable_vpid();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_wbinvd_exiting();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_unrestricted_guest();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_apic_register_virtualization();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_virtual_interrupt_delivery();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_pause_loop_exiting();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_rdrand_exiting();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_enable_invpcid();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_enable_vm_functions();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_vmcs_shadowing();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_rdseed_exiting();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_enable_pml();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_ept_violation_ve();
    this->test_vmcs_secondary_processor_based_vm_execution_controls_enable_xsaves_xrstors();
    this->test_vmcs_ple_gap();
    this->test_vmcs_ple_window();
}


void
vmcs_ut::list_32bit_read_only_data_fields()
{
    this->test_vmcs_vm_instruction_error();
    this->test_vmcs_vm_instruction_error_description();
    this->test_vmcs_vm_instruction_error_description_if_exists();
    this->test_vmcs_exit_reason();
    this->test_vmcs_exit_reason_basic_exit_reason();
    this->test_vmcs_exit_reason_basic_exit_reason_description();
    this->test_vmcs_exit_reason_basic_exit_reason_description_if_exists();
    this->test_vmcs_exit_reason_reserved();
    this->test_vmcs_exit_reason_vm_exit_incident_to_enclave_mode();
    this->test_vmcs_exit_reason_pending_mtf_vm_exit();
    this->test_vmcs_exit_reason_vm_exit_from_vmx_root_operation();
    this->test_vmcs_exit_reason_vm_entry_failure();
    this->test_vmcs_vm_exit_interruption_information();
    this->test_vmcs_vm_exit_interruption_information_vector();
    this->test_vmcs_vm_exit_interruption_information_interruption_type();
    this->test_vmcs_vm_exit_interruption_information_error_code_valid();
    this->test_vmcs_vm_exit_interruption_information_nmi_blocking_due_to_iret();
    this->test_vmcs_vm_exit_interruption_information_reserved();
    this->test_vmcs_vm_exit_interruption_information_valid_bit();
    this->test_vmcs_vm_exit_interruption_error_code();
    this->test_vmcs_idt_vectoring_information();
    this->test_vmcs_idt_vectoring_information_vector();
    this->test_vmcs_idt_vectoring_information_interruption_type();
    this->test_vmcs_idt_vectoring_information_error_code_valid();
    this->test_vmcs_idt_vectoring_information_reserved();
    this->test_vmcs_idt_vectoring_information_valid_bit();
    this->test_vmcs_idt_vectoring_information();
    this->test_vmcs_idt_vectoring_error_code();
    this->test_vmcs_vm_exit_instruction_length();
    this->test_vmcs_vm_exit_instruction_information();
    this->test_vmcs_vm_exit_instruction_information_ins();
    this->test_vmcs_vm_exit_instruction_information_ins_address_size();
    this->test_vmcs_vm_exit_instruction_information_outs();
    this->test_vmcs_vm_exit_instruction_information_outs_address_size();
    this->test_vmcs_vm_exit_instruction_information_outs_segment_register();
    this->test_vmcs_vm_exit_instruction_information_invept();
    this->test_vmcs_vm_exit_instruction_information_invept_scaling();
    this->test_vmcs_vm_exit_instruction_information_invept_address_size();
    this->test_vmcs_vm_exit_instruction_information_invept_segment_register();
    this->test_vmcs_vm_exit_instruction_information_invept_index_reg();
    this->test_vmcs_vm_exit_instruction_information_invept_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_invept_base_reg();
    this->test_vmcs_vm_exit_instruction_information_invept_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_invept_reg2();
    this->test_vmcs_vm_exit_instruction_information_invpcid();
    this->test_vmcs_vm_exit_instruction_information_invpcid_scaling();
    this->test_vmcs_vm_exit_instruction_information_invpcid_address_size();
    this->test_vmcs_vm_exit_instruction_information_invpcid_segment_register();
    this->test_vmcs_vm_exit_instruction_information_invpcid_index_reg();
    this->test_vmcs_vm_exit_instruction_information_invpcid_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_invpcid_base_reg();
    this->test_vmcs_vm_exit_instruction_information_invpcid_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_invpcid_reg2();
    this->test_vmcs_vm_exit_instruction_information_invvpid();
    this->test_vmcs_vm_exit_instruction_information_invvpid_scaling();
    this->test_vmcs_vm_exit_instruction_information_invvpid_address_size();
    this->test_vmcs_vm_exit_instruction_information_invvpid_segment_register();
    this->test_vmcs_vm_exit_instruction_information_invvpid_index_reg();
    this->test_vmcs_vm_exit_instruction_information_invvpid_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_invvpid_base_reg();
    this->test_vmcs_vm_exit_instruction_information_invvpid_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_invvpid_reg2();
    this->test_vmcs_vm_exit_instruction_information_lidt();
    this->test_vmcs_vm_exit_instruction_information_lidt_scaling();
    this->test_vmcs_vm_exit_instruction_information_lidt_address_size();
    this->test_vmcs_vm_exit_instruction_information_lidt_operand_size();
    this->test_vmcs_vm_exit_instruction_information_lidt_segment_register();
    this->test_vmcs_vm_exit_instruction_information_lidt_index_reg();
    this->test_vmcs_vm_exit_instruction_information_lidt_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_lidt_base_reg();
    this->test_vmcs_vm_exit_instruction_information_lidt_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_lidt_instruction_identity();
    this->test_vmcs_vm_exit_instruction_information_lgdt();
    this->test_vmcs_vm_exit_instruction_information_lgdt_scaling();
    this->test_vmcs_vm_exit_instruction_information_lgdt_address_size();
    this->test_vmcs_vm_exit_instruction_information_lgdt_operand_size();
    this->test_vmcs_vm_exit_instruction_information_lgdt_segment_register();
    this->test_vmcs_vm_exit_instruction_information_lgdt_index_reg();
    this->test_vmcs_vm_exit_instruction_information_lgdt_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_lgdt_base_reg();
    this->test_vmcs_vm_exit_instruction_information_lgdt_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_lgdt_instruction_identity();
    this->test_vmcs_vm_exit_instruction_information_sidt();
    this->test_vmcs_vm_exit_instruction_information_sidt_scaling();
    this->test_vmcs_vm_exit_instruction_information_sidt_address_size();
    this->test_vmcs_vm_exit_instruction_information_sidt_operand_size();
    this->test_vmcs_vm_exit_instruction_information_sidt_segment_register();
    this->test_vmcs_vm_exit_instruction_information_sidt_index_reg();
    this->test_vmcs_vm_exit_instruction_information_sidt_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_sidt_base_reg();
    this->test_vmcs_vm_exit_instruction_information_sidt_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_sidt_instruction_identity();
    this->test_vmcs_vm_exit_instruction_information_sgdt();
    this->test_vmcs_vm_exit_instruction_information_sgdt_scaling();
    this->test_vmcs_vm_exit_instruction_information_sgdt_address_size();
    this->test_vmcs_vm_exit_instruction_information_sgdt_operand_size();
    this->test_vmcs_vm_exit_instruction_information_sgdt_segment_register();
    this->test_vmcs_vm_exit_instruction_information_sgdt_index_reg();
    this->test_vmcs_vm_exit_instruction_information_sgdt_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_sgdt_base_reg();
    this->test_vmcs_vm_exit_instruction_information_sgdt_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_sgdt_instruction_identity();
    this->test_vmcs_vm_exit_instruction_information_lldt();
    this->test_vmcs_vm_exit_instruction_information_lldt_scaling();
    this->test_vmcs_vm_exit_instruction_information_lldt_reg1();
    this->test_vmcs_vm_exit_instruction_information_lldt_address_size();
    this->test_vmcs_vm_exit_instruction_information_lldt_mem_reg();
    this->test_vmcs_vm_exit_instruction_information_lldt_segment_register();
    this->test_vmcs_vm_exit_instruction_information_lldt_index_reg();
    this->test_vmcs_vm_exit_instruction_information_lldt_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_lldt_base_reg();
    this->test_vmcs_vm_exit_instruction_information_lldt_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_lldt_instruction_identity();
    this->test_vmcs_vm_exit_instruction_information_ltr();
    this->test_vmcs_vm_exit_instruction_information_ltr_scaling();
    this->test_vmcs_vm_exit_instruction_information_ltr_reg1();
    this->test_vmcs_vm_exit_instruction_information_ltr_address_size();
    this->test_vmcs_vm_exit_instruction_information_ltr_mem_reg();
    this->test_vmcs_vm_exit_instruction_information_ltr_segment_register();
    this->test_vmcs_vm_exit_instruction_information_ltr_index_reg();
    this->test_vmcs_vm_exit_instruction_information_ltr_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_ltr_base_reg();
    this->test_vmcs_vm_exit_instruction_information_ltr_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_ltr_instruction_identity();
    this->test_vmcs_vm_exit_instruction_information_sldt();
    this->test_vmcs_vm_exit_instruction_information_sldt_scaling();
    this->test_vmcs_vm_exit_instruction_information_sldt_reg1();
    this->test_vmcs_vm_exit_instruction_information_sldt_address_size();
    this->test_vmcs_vm_exit_instruction_information_sldt_mem_reg();
    this->test_vmcs_vm_exit_instruction_information_sldt_segment_register();
    this->test_vmcs_vm_exit_instruction_information_sldt_index_reg();
    this->test_vmcs_vm_exit_instruction_information_sldt_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_sldt_base_reg();
    this->test_vmcs_vm_exit_instruction_information_sldt_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_sldt_instruction_identity();
    this->test_vmcs_vm_exit_instruction_information_str();
    this->test_vmcs_vm_exit_instruction_information_str_scaling();
    this->test_vmcs_vm_exit_instruction_information_str_reg1();
    this->test_vmcs_vm_exit_instruction_information_str_address_size();
    this->test_vmcs_vm_exit_instruction_information_str_mem_reg();
    this->test_vmcs_vm_exit_instruction_information_str_segment_register();
    this->test_vmcs_vm_exit_instruction_information_str_index_reg();
    this->test_vmcs_vm_exit_instruction_information_str_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_str_base_reg();
    this->test_vmcs_vm_exit_instruction_information_str_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_str_instruction_identity();
    this->test_vmcs_vm_exit_instruction_information_rdrand();
    this->test_vmcs_vm_exit_instruction_information_rdrand_destination_register();
    this->test_vmcs_vm_exit_instruction_information_rdrand_operand_size();
    this->test_vmcs_vm_exit_instruction_information_rdseed();
    this->test_vmcs_vm_exit_instruction_information_rdseed_destination_register();
    this->test_vmcs_vm_exit_instruction_information_rdseed_operand_size();
    this->test_vmcs_vm_exit_instruction_information_vmclear();
    this->test_vmcs_vm_exit_instruction_information_vmclear_scaling();
    this->test_vmcs_vm_exit_instruction_information_vmclear_address_size();
    this->test_vmcs_vm_exit_instruction_information_vmclear_segment_register();
    this->test_vmcs_vm_exit_instruction_information_vmclear_index_reg();
    this->test_vmcs_vm_exit_instruction_information_vmclear_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmclear_base_reg();
    this->test_vmcs_vm_exit_instruction_information_vmclear_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmptrld();
    this->test_vmcs_vm_exit_instruction_information_vmptrld_scaling();
    this->test_vmcs_vm_exit_instruction_information_vmptrld_address_size();
    this->test_vmcs_vm_exit_instruction_information_vmptrld_segment_register();
    this->test_vmcs_vm_exit_instruction_information_vmptrld_index_reg();
    this->test_vmcs_vm_exit_instruction_information_vmptrld_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmptrld_base_reg();
    this->test_vmcs_vm_exit_instruction_information_vmptrld_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmptrst();
    this->test_vmcs_vm_exit_instruction_information_vmptrst_scaling();
    this->test_vmcs_vm_exit_instruction_information_vmptrst_address_size();
    this->test_vmcs_vm_exit_instruction_information_vmptrst_segment_register();
    this->test_vmcs_vm_exit_instruction_information_vmptrst_index_reg();
    this->test_vmcs_vm_exit_instruction_information_vmptrst_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmptrst_base_reg();
    this->test_vmcs_vm_exit_instruction_information_vmptrst_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmxon();
    this->test_vmcs_vm_exit_instruction_information_vmxon_scaling();
    this->test_vmcs_vm_exit_instruction_information_vmxon_address_size();
    this->test_vmcs_vm_exit_instruction_information_vmxon_segment_register();
    this->test_vmcs_vm_exit_instruction_information_vmxon_index_reg();
    this->test_vmcs_vm_exit_instruction_information_vmxon_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmxon_base_reg();
    this->test_vmcs_vm_exit_instruction_information_vmxon_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_xrstors();
    this->test_vmcs_vm_exit_instruction_information_xrstors_scaling();
    this->test_vmcs_vm_exit_instruction_information_xrstors_address_size();
    this->test_vmcs_vm_exit_instruction_information_xrstors_segment_register();
    this->test_vmcs_vm_exit_instruction_information_xrstors_index_reg();
    this->test_vmcs_vm_exit_instruction_information_xrstors_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_xrstors_base_reg();
    this->test_vmcs_vm_exit_instruction_information_xrstors_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_xsaves();
    this->test_vmcs_vm_exit_instruction_information_xsaves_scaling();
    this->test_vmcs_vm_exit_instruction_information_xsaves_address_size();
    this->test_vmcs_vm_exit_instruction_information_xsaves_segment_register();
    this->test_vmcs_vm_exit_instruction_information_xsaves_index_reg();
    this->test_vmcs_vm_exit_instruction_information_xsaves_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_xsaves_base_reg();
    this->test_vmcs_vm_exit_instruction_information_xsaves_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmread();
    this->test_vmcs_vm_exit_instruction_information_vmread_scaling();
    this->test_vmcs_vm_exit_instruction_information_vmread_reg1();
    this->test_vmcs_vm_exit_instruction_information_vmread_address_size();
    this->test_vmcs_vm_exit_instruction_information_vmread_mem_reg();
    this->test_vmcs_vm_exit_instruction_information_vmread_segment_register();
    this->test_vmcs_vm_exit_instruction_information_vmread_index_reg();
    this->test_vmcs_vm_exit_instruction_information_vmread_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmread_base_reg();
    this->test_vmcs_vm_exit_instruction_information_vmread_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmread_reg2();
    this->test_vmcs_vm_exit_instruction_information_vmwrite();
    this->test_vmcs_vm_exit_instruction_information_vmwrite_scaling();
    this->test_vmcs_vm_exit_instruction_information_vmwrite_reg1();
    this->test_vmcs_vm_exit_instruction_information_vmwrite_address_size();
    this->test_vmcs_vm_exit_instruction_information_vmwrite_mem_reg();
    this->test_vmcs_vm_exit_instruction_information_vmwrite_segment_register();
    this->test_vmcs_vm_exit_instruction_information_vmwrite_index_reg();
    this->test_vmcs_vm_exit_instruction_information_vmwrite_index_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmwrite_base_reg();
    this->test_vmcs_vm_exit_instruction_information_vmwrite_base_reg_invalid();
    this->test_vmcs_vm_exit_instruction_information_vmwrite_reg2();
}

void
vmcs_ut::list_32bit_guest_state_fields()
{
    this->test_vmcs_guest_es_limit();
    this->test_vmcs_guest_cs_limit();
    this->test_vmcs_guest_ss_limit();
    this->test_vmcs_guest_ds_limit();
    this->test_vmcs_guest_fs_limit();
    this->test_vmcs_guest_gs_limit();
    this->test_vmcs_guest_ldtr_limit();
    this->test_vmcs_guest_tr_limit();
    this->test_vmcs_guest_gdtr_limit();
    this->test_vmcs_guest_idtr_limit();
    this->test_vmcs_guest_es_access_rights();
    this->test_vmcs_guest_es_access_rights_type();
    this->test_vmcs_guest_es_access_rights_s();
    this->test_vmcs_guest_es_access_rights_dpl();
    this->test_vmcs_guest_es_access_rights_present();
    this->test_vmcs_guest_es_access_rights_avl();
    this->test_vmcs_guest_es_access_rights_l();
    this->test_vmcs_guest_es_access_rights_db();
    this->test_vmcs_guest_es_access_rights_granularity();
    this->test_vmcs_guest_es_access_rights_reserved();
    this->test_vmcs_guest_es_access_rights_unusable();
    this->test_vmcs_guest_cs_access_rights();
    this->test_vmcs_guest_cs_access_rights_type();
    this->test_vmcs_guest_cs_access_rights_s();
    this->test_vmcs_guest_cs_access_rights_dpl();
    this->test_vmcs_guest_cs_access_rights_present();
    this->test_vmcs_guest_cs_access_rights_avl();
    this->test_vmcs_guest_cs_access_rights_l();
    this->test_vmcs_guest_cs_access_rights_db();
    this->test_vmcs_guest_cs_access_rights_granularity();
    this->test_vmcs_guest_cs_access_rights_reserved();
    this->test_vmcs_guest_cs_access_rights_unusable();
    this->test_vmcs_guest_ss_access_rights();
    this->test_vmcs_guest_ss_access_rights_type();
    this->test_vmcs_guest_ss_access_rights_s();
    this->test_vmcs_guest_ss_access_rights_dpl();
    this->test_vmcs_guest_ss_access_rights_present();
    this->test_vmcs_guest_ss_access_rights_avl();
    this->test_vmcs_guest_ss_access_rights_l();
    this->test_vmcs_guest_ss_access_rights_db();
    this->test_vmcs_guest_ss_access_rights_granularity();
    this->test_vmcs_guest_ss_access_rights_reserved();
    this->test_vmcs_guest_ss_access_rights_unusable();
    this->test_vmcs_guest_ds_access_rights();
    this->test_vmcs_guest_ds_access_rights_type();
    this->test_vmcs_guest_ds_access_rights_s();
    this->test_vmcs_guest_ds_access_rights_dpl();
    this->test_vmcs_guest_ds_access_rights_present();
    this->test_vmcs_guest_ds_access_rights_avl();
    this->test_vmcs_guest_ds_access_rights_l();
    this->test_vmcs_guest_ds_access_rights_db();
    this->test_vmcs_guest_ds_access_rights_granularity();
    this->test_vmcs_guest_ds_access_rights_reserved();
    this->test_vmcs_guest_ds_access_rights_unusable();
    this->test_vmcs_guest_fs_access_rights();
    this->test_vmcs_guest_fs_access_rights_type();
    this->test_vmcs_guest_fs_access_rights_s();
    this->test_vmcs_guest_fs_access_rights_dpl();
    this->test_vmcs_guest_fs_access_rights_present();
    this->test_vmcs_guest_fs_access_rights_avl();
    this->test_vmcs_guest_fs_access_rights_l();
    this->test_vmcs_guest_fs_access_rights_db();
    this->test_vmcs_guest_fs_access_rights_granularity();
    this->test_vmcs_guest_fs_access_rights_reserved();
    this->test_vmcs_guest_fs_access_rights_unusable();
    this->test_vmcs_guest_gs_access_rights();
    this->test_vmcs_guest_gs_access_rights_type();
    this->test_vmcs_guest_gs_access_rights_s();
    this->test_vmcs_guest_gs_access_rights_dpl();
    this->test_vmcs_guest_gs_access_rights_present();
    this->test_vmcs_guest_gs_access_rights_avl();
    this->test_vmcs_guest_gs_access_rights_l();
    this->test_vmcs_guest_gs_access_rights_db();
    this->test_vmcs_guest_gs_access_rights_granularity();
    this->test_vmcs_guest_gs_access_rights_reserved();
    this->test_vmcs_guest_gs_access_rights_unusable();
    this->test_vmcs_guest_ldtr_access_rights();
    this->test_vmcs_guest_ldtr_access_rights_type();
    this->test_vmcs_guest_ldtr_access_rights_s();
    this->test_vmcs_guest_ldtr_access_rights_dpl();
    this->test_vmcs_guest_ldtr_access_rights_present();
    this->test_vmcs_guest_ldtr_access_rights_avl();
    this->test_vmcs_guest_ldtr_access_rights_l();
    this->test_vmcs_guest_ldtr_access_rights_db();
    this->test_vmcs_guest_ldtr_access_rights_granularity();
    this->test_vmcs_guest_ldtr_access_rights_reserved();
    this->test_vmcs_guest_ldtr_access_rights_unusable();
    this->test_vmcs_guest_tr_access_rights();
    this->test_vmcs_guest_tr_access_rights_type();
    this->test_vmcs_guest_tr_access_rights_s();
    this->test_vmcs_guest_tr_access_rights_dpl();
    this->test_vmcs_guest_tr_access_rights_present();
    this->test_vmcs_guest_tr_access_rights_avl();
    this->test_vmcs_guest_tr_access_rights_l();
    this->test_vmcs_guest_tr_access_rights_db();
    this->test_vmcs_guest_tr_access_rights_granularity();
    this->test_vmcs_guest_tr_access_rights_reserved();
    this->test_vmcs_guest_tr_access_rights_unusable();
    this->test_vmcs_guest_interruptibility_state();
    this->test_vmcs_guest_interruptibility_state_blocking_by_sti();
    this->test_vmcs_guest_interruptibility_state_blocking_by_mov_ss();
    this->test_vmcs_guest_interruptibility_state_blocking_by_smi();
    this->test_vmcs_guest_interruptibility_state_blocking_by_nmi();
    this->test_vmcs_guest_interruptibility_state_enclave_interruption();
    this->test_vmcs_guest_interruptibility_state_reserved();
    this->test_vmcs_guest_activity_state();
    this->test_vmcs_guest_smbase();
    this->test_vmcs_guest_ia32_sysenter_cs();
    this->test_vmcs_vmx_preemption_timer_value();
}

void
vmcs_ut::list_32bit_host_state_field()
{
    this->test_vmcs_host_ia32_sysenter_cs();
}

void
vmcs_ut::list_natural_width_control_fields()
{
    this->test_vmcs_cr0_guest_host_mask();
    this->test_vmcs_cr4_guest_host_mask();
    this->test_vmcs_cr0_read_shadow();
    this->test_vmcs_cr4_read_shadow();
    this->test_vmcs_cr3_target_value_0();
    this->test_vmcs_cr3_target_value_1();
    this->test_vmcs_cr3_target_value_2();
    this->test_vmcs_cr3_target_value_3();
}

void
vmcs_ut::list_natural_width_read_only_data_fields()
{
    this->test_vmcs_exit_qualification();
    this->test_vmcs_exit_qualification_debug_exception();
    this->test_vmcs_exit_qualification_debug_exception_b0();
    this->test_vmcs_exit_qualification_debug_exception_b1();
    this->test_vmcs_exit_qualification_debug_exception_b2();
    this->test_vmcs_exit_qualification_debug_exception_b3();
    this->test_vmcs_exit_qualification_debug_exception_reserved();
    this->test_vmcs_exit_qualification_debug_exception_bd();
    this->test_vmcs_exit_qualification_debug_exception_bs();
    this->test_vmcs_exit_qualification_page_fault_exception();
    this->test_vmcs_exit_qualification_sipi();
    this->test_vmcs_exit_qualification_sipi_vector();
    this->test_vmcs_exit_qualification_task_switch();
    this->test_vmcs_exit_qualification_task_switch_tss_selector();
    this->test_vmcs_exit_qualification_task_switch_reserved();
    this->test_vmcs_exit_qualification_task_switch_source_of_task_switch_init();
    this->test_vmcs_exit_qualification_invept();
    this->test_vmcs_exit_qualification_invpcid();
    this->test_vmcs_exit_qualification_invvpid();
    this->test_vmcs_exit_qualification_lgdt();
    this->test_vmcs_exit_qualification_lidt();
    this->test_vmcs_exit_qualification_lldt();
    this->test_vmcs_exit_qualification_ltr();
    this->test_vmcs_exit_qualification_sgdt();
    this->test_vmcs_exit_qualification_sidt();
    this->test_vmcs_exit_qualification_sldt();
    this->test_vmcs_exit_qualification_str();
    this->test_vmcs_exit_qualification_vmclear();
    this->test_vmcs_exit_qualification_vmptrld();
    this->test_vmcs_exit_qualification_vmread();
    this->test_vmcs_exit_qualification_vmwrite();
    this->test_vmcs_exit_qualification_vmxon();
    this->test_vmcs_exit_qualification_xrstors();
    this->test_vmcs_exit_qualification_xsaves();
    this->test_vmcs_exit_qualification_control_register_access();
    this->test_vmcs_exit_qualification_control_register_access_control_register_number();
    this->test_vmcs_exit_qualification_control_register_access_access_type();
    this->test_vmcs_exit_qualification_control_register_access_lmsw_operand_type();
    this->test_vmcs_exit_qualification_control_register_access_reserved();
    this->test_vmcs_exit_qualification_control_register_access_general_purpose_register();
    this->test_vmcs_exit_qualification_control_register_access_source_data();
    this->test_vmcs_exit_qualification_mov_dr();
    this->test_vmcs_exit_qualification_mov_dr_debug_register_number();
    this->test_vmcs_exit_qualification_mov_dr_reserved();
    this->test_vmcs_exit_qualification_mov_dr_direction_of_access();
    this->test_vmcs_exit_qualification_mov_dr_general_purpose_register();
    this->test_vmcs_exit_qualification_io_instruction();
    this->test_vmcs_exit_qualification_io_instruction_size_of_access();
    this->test_vmcs_exit_qualification_io_instruction_direction_of_access();
    this->test_vmcs_exit_qualification_io_instruction_string_instruction();
    this->test_vmcs_exit_qualification_io_instruction_rep_prefixed();
    this->test_vmcs_exit_qualification_io_instruction_operand_encoding();
    this->test_vmcs_exit_qualification_io_instruction_reserved();
    this->test_vmcs_exit_qualification_io_instruction_port_number();
    this->test_vmcs_exit_qualification_mwait();
    this->test_vmcs_exit_qualification_linear_apic_access();
    this->test_vmcs_exit_qualification_linear_apic_access_offset();
    this->test_vmcs_exit_qualification_linear_apic_access_access_type();
    this->test_vmcs_exit_qualification_linear_apic_access_reserved();
    this->test_vmcs_exit_qualification_guest_physical_apic_access();
    this->test_vmcs_exit_qualification_guest_physical_apic_access_access_type();
    this->test_vmcs_exit_qualification_guest_physical_apic_access_reserved();
    this->test_vmcs_exit_qualification_ept_violation();
    this->test_vmcs_exit_qualification_ept_violation_data_read();
    this->test_vmcs_exit_qualification_ept_violation_data_write();
    this->test_vmcs_exit_qualification_ept_violation_instruction_fetch();
    this->test_vmcs_exit_qualification_ept_violation_readable();
    this->test_vmcs_exit_qualification_ept_violation_writeable();
    this->test_vmcs_exit_qualification_ept_violation_executable();
    this->test_vmcs_exit_qualification_ept_violation_reserved();
    this->test_vmcs_exit_qualification_ept_violation_valid_guest_linear_address();
    this->test_vmcs_exit_qualification_ept_violation_nmi_unblocking_due_to_iret();
    this->test_vmcs_exit_qualification_eoi_virtualization();
    this->test_vmcs_exit_qualification_eoi_virtualization_vector();
    this->test_vmcs_exit_qualification_apic_write();
    this->test_vmcs_exit_qualification_apic_write_offset();
    this->test_vmcs_io_rcx();
    this->test_vmcs_io_rsi();
    this->test_vmcs_io_rdi();
    this->test_vmcs_io_rip();
    this->test_vmcs_guest_linear_address();
}

void
vmcs_ut::list_natural_width_guest_state_fields()
{
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
    this->test_vmcs_guest_es_base();
    this->test_vmcs_guest_cs_base();
    this->test_vmcs_guest_ss_base();
    this->test_vmcs_guest_ds_base();
    this->test_vmcs_guest_fs_base();
    this->test_vmcs_guest_gs_base();
    this->test_vmcs_guest_ldtr_base();
    this->test_vmcs_guest_tr_base();
    this->test_vmcs_guest_gdtr_base();
    this->test_vmcs_guest_idtr_base();
    this->test_vmcs_guest_dr7();
    this->test_vmcs_guest_rsp();
    this->test_vmcs_guest_rip();
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
    this->test_vmcs_guest_pending_debug_exceptions();
    this->test_vmcs_guest_pending_debug_exceptions_b0();
    this->test_vmcs_guest_pending_debug_exceptions_b1();
    this->test_vmcs_guest_pending_debug_exceptions_b2();
    this->test_vmcs_guest_pending_debug_exceptions_b3();
    this->test_vmcs_guest_pending_debug_exceptions_reserved();
    this->test_vmcs_guest_pending_debug_exceptions_enabled_breakpoint();
    this->test_vmcs_guest_pending_debug_exceptions_bs();
    this->test_vmcs_guest_pending_debug_exceptions_rtm();
    this->test_vmcs_guest_ia32_sysenter_esp();
    this->test_vmcs_guest_ia32_sysenter_eip();
}

void
vmcs_ut::list_natural_width_host_state_fields()
{
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
    this->test_vmcs_host_fs_base();
    this->test_vmcs_host_gs_base();
    this->test_vmcs_host_tr_base();
    this->test_vmcs_host_gdtr_base();
    this->test_vmcs_host_idtr_base();
    this->test_vmcs_host_ia32_sysenter_esp();
    this->test_vmcs_host_ia32_sysenter_eip();
    this->test_vmcs_host_rsp();
    this->test_vmcs_host_rip();
}

void
vmcs_ut::list_checks_on_vmx_controls()
{
    this->test_check_control_vmx_controls_all();
    this->test_check_control_vm_execution_control_fields_all();
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
    this->test_check_control_unrestricted_guests();
    this->test_check_control_enable_vm_functions();
    this->test_check_control_enable_vmcs_shadowing();
    this->test_check_control_enable_ept_violation_checks();
    this->test_check_control_enable_pml_checks();

    this->test_check_control_vm_exit_control_fields_all();
    this->test_check_control_vm_exit_ctls_reserved_properly_set();
    this->test_check_control_activate_and_save_preemption_timer_must_be_0();
    this->test_check_control_exit_msr_store_address();
    this->test_check_control_exit_msr_load_address();

    this->test_check_control_vm_entry_control_fields_all();
    this->test_check_control_vm_entry_ctls_reserved_properly_set();
    this->test_check_control_event_injection_type_vector_checks();
    this->test_check_control_event_injection_delivery_ec_checks();
    this->test_check_control_event_injection_reserved_bits_checks();
    this->test_check_control_event_injection_ec_checks();
    this->test_check_control_event_injection_instr_length_checks();
    this->test_check_control_entry_msr_load_address();
}

void
vmcs_ut::list_checks_on_host_state()
{
    this->test_check_host_state_all();
    this->test_check_host_control_registers_and_msrs_all();
    this->test_check_host_cr0_for_unsupported_bits();
    this->test_check_host_cr4_for_unsupported_bits();
    this->test_check_host_cr3_for_unsupported_bits();
    this->test_check_host_ia32_sysenter_esp_canonical_address();
    this->test_check_host_ia32_sysenter_eip_canonical_address();
    this->test_check_host_verify_load_ia32_perf_global_ctrl();
    this->test_check_host_verify_load_ia32_pat();
    this->test_check_host_verify_load_ia32_efer();

    this->test_check_host_segment_and_descriptor_table_registers_all();
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

    this->test_check_host_address_space_size_all();
    this->test_check_host_if_outside_ia32e_mode();
    this->test_check_host_address_space_size_exit_ctl_is_set();
    this->test_check_host_address_space_disabled();
    this->test_check_host_address_space_enabled();
}

void
vmcs_ut::list_checks_on_guest_state()
{
    this->test_check_guest_state_all();
    this->test_check_guest_control_registers_debug_registers_and_msrs_all();
    this->test_check_guest_cr0_for_unsupported_bits();
    this->test_check_guest_cr0_verify_paging_enabled();
    this->test_check_guest_cr4_for_unsupported_bits();
    this->test_check_guest_load_debug_controls_verify_reserved();
    this->test_check_guest_verify_ia_32e_mode_enabled();
    this->test_check_guest_verify_ia_32e_mode_disabled();
    this->test_check_guest_cr3_for_unsupported_bits();
    this->test_check_guest_load_debug_controls_verify_dr7();
    this->test_check_guest_ia32_sysenter_esp_canonical_address();
    this->test_check_guest_ia32_sysenter_eip_canonical_address();
    this->test_check_guest_verify_load_ia32_perf_global_ctrl();
    this->test_check_guest_verify_load_ia32_pat();
    this->test_check_guest_verify_load_ia32_efer();
    this->test_check_guest_verify_load_ia32_bndcfgs();

    this->test_check_guest_segment_registers_all();
    this->test_check_guest_tr_ti_bit_equals_0();
    this->test_check_guest_ldtr_ti_bit_equals_0();
    this->test_check_guest_ss_and_cs_rpl_are_the_same();
    this->test_check_guest_cs_base_is_shifted();
    this->test_check_guest_ss_base_is_shifted();
    this->test_check_guest_ds_base_is_shifted();
    this->test_check_guest_es_base_is_shifted();
    this->test_check_guest_fs_base_is_shifted();
    this->test_check_guest_gs_base_is_shifted();
    this->test_check_guest_tr_base_is_canonical();
    this->test_check_guest_fs_base_is_canonical();
    this->test_check_guest_gs_base_is_canonical();
    this->test_check_guest_ldtr_base_is_canonical();
    this->test_check_guest_cs_base_upper_dword_0();
    this->test_check_guest_ss_base_upper_dword_0();
    this->test_check_guest_ds_base_upper_dword_0();
    this->test_check_guest_es_base_upper_dword_0();
    this->test_check_guest_cs_limit();
    this->test_check_guest_ss_limit();
    this->test_check_guest_ds_limit();
    this->test_check_guest_es_limit();
    this->test_check_guest_gs_limit();
    this->test_check_guest_fs_limit();
    this->test_check_guest_v8086_cs_access_rights();
    this->test_check_guest_v8086_ss_access_rights();
    this->test_check_guest_v8086_ds_access_rights();
    this->test_check_guest_v8086_es_access_rights();
    this->test_check_guest_v8086_fs_access_rights();
    this->test_check_guest_v8086_gs_access_rights();
    this->test_check_guest_cs_access_rights_type();
    this->test_check_guest_ss_access_rights_type();
    this->test_check_guest_ds_access_rights_type();
    this->test_check_guest_es_access_rights_type();
    this->test_check_guest_fs_access_rights_type();
    this->test_check_guest_gs_access_rights_type();
    this->test_check_guest_cs_is_not_a_system_descriptor();
    this->test_check_guest_ss_is_not_a_system_descriptor();
    this->test_check_guest_ds_is_not_a_system_descriptor();
    this->test_check_guest_es_is_not_a_system_descriptor();
    this->test_check_guest_fs_is_not_a_system_descriptor();
    this->test_check_guest_gs_is_not_a_system_descriptor();
    this->test_check_guest_cs_type_not_equal_3();
    this->test_check_guest_cs_dpl_adheres_to_ss_dpl();
    this->test_check_guest_ss_dpl_must_equal_rpl();
    this->test_check_guest_ss_dpl_must_equal_zero();
    this->test_check_guest_ds_dpl();
    this->test_check_guest_es_dpl();
    this->test_check_guest_fs_dpl();
    this->test_check_guest_gs_dpl();
    this->test_check_guest_cs_must_be_present();
    this->test_check_guest_ss_must_be_present_if_usable();
    this->test_check_guest_ds_must_be_present_if_usable();
    this->test_check_guest_es_must_be_present_if_usable();
    this->test_check_guest_fs_must_be_present_if_usable();
    this->test_check_guest_gs_must_be_present_if_usable();
    this->test_check_guest_cs_access_rights_reserved_must_be_0();
    this->test_check_guest_ss_access_rights_reserved_must_be_0();
    this->test_check_guest_ds_access_rights_reserved_must_be_0();
    this->test_check_guest_es_access_rights_reserved_must_be_0();
    this->test_check_guest_fs_access_rights_reserved_must_be_0();
    this->test_check_guest_gs_access_rights_reserved_must_be_0();
    this->test_check_guest_cs_db_must_be_0_if_l_equals_1();
    this->test_check_guest_cs_granularity();
    this->test_check_guest_ss_granularity();
    this->test_check_guest_ds_granularity();
    this->test_check_guest_es_granularity();
    this->test_check_guest_fs_granularity();
    this->test_check_guest_gs_granularity();
    this->test_check_guest_cs_access_rights_remaining_reserved_bit_0();
    this->test_check_guest_ss_access_rights_remaining_reserved_bit_0();
    this->test_check_guest_ds_access_rights_remaining_reserved_bit_0();
    this->test_check_guest_es_access_rights_remaining_reserved_bit_0();
    this->test_check_guest_fs_access_rights_remaining_reserved_bit_0();
    this->test_check_guest_gs_access_rights_remaining_reserved_bit_0();
    this->test_check_guest_tr_type_must_be_11();
    this->test_check_guest_tr_must_be_a_system_descriptor();
    this->test_check_guest_tr_must_be_present();
    this->test_check_guest_tr_access_rights_reserved_must_be_0();
    this->test_check_guest_tr_granularity();
    this->test_check_guest_tr_must_be_usable();
    this->test_check_guest_tr_access_rights_remaining_reserved_bit_0();
    this->test_check_guest_ldtr_type_must_be_2();
    this->test_check_guest_ldtr_must_be_a_system_descriptor();
    this->test_check_guest_ldtr_must_be_present();
    this->test_check_guest_ldtr_access_rights_reserved_must_be_0();
    this->test_check_guest_ldtr_granularity();
    this->test_check_guest_ldtr_access_rights_remaining_reserved_bit_0();

    this->test_check_guest_descriptor_table_registers_all();
    this->test_check_guest_gdtr_base_must_be_canonical();
    this->test_check_guest_idtr_base_must_be_canonical();
    this->test_check_guest_gdtr_limit_reserved_bits();
    this->test_check_guest_idtr_limit_reserved_bits();

    this->test_check_guest_rip_and_rflags_all();
    this->test_check_guest_rip_upper_bits();
    this->test_check_guest_rip_valid_addr();
    this->test_check_guest_rflags_reserved_bits();
    this->test_check_guest_rflags_vm_bit();
    this->test_check_guest_rflag_interrupt_enable();

    this->test_check_guest_non_register_state_all();
    this->test_check_guest_valid_activity_state();
    this->test_check_guest_activity_state_not_hlt_when_dpl_not_0();
    this->test_check_guest_must_be_active_if_injecting_blocking_state();
    this->test_check_guest_hlt_valid_interrupts();
    this->test_check_guest_shutdown_valid_interrupts();
    this->test_check_guest_sipi_valid_interrupts();
    this->test_check_guest_valid_activity_state_and_smm();
    this->test_check_guest_interruptibility_state_reserved();
    this->test_check_guest_interruptibility_state_sti_mov_ss();
    this->test_check_guest_interruptibility_state_sti();
    this->test_check_guest_interruptibility_state_external_interrupt();
    this->test_check_guest_interruptibility_state_nmi();
    this->test_check_guest_interruptibility_not_in_smm();
    this->test_check_guest_interruptibility_entry_to_smm();
    this->test_check_guest_interruptibility_state_sti_and_nmi();
    this->test_check_guest_interruptibility_state_virtual_nmi();
    this->test_check_guest_interruptibility_state_enclave_interrupt();
    this->test_check_guest_pending_debug_exceptions_reserved();
    this->test_check_guest_pending_debug_exceptions_dbg_ctl();
    this->test_check_guest_pending_debug_exceptions_rtm();
    this->test_check_guest_vmcs_link_pointer_bits_11_0();
    this->test_check_guest_vmcs_link_pointer_valid_addr();
    this->test_check_guest_vmcs_link_pointer_first_word();

    this->test_check_guest_pdptes_all();
    this->test_check_guest_valid_pdpte_with_ept_disabled();
    this->test_check_guest_valid_pdpte_with_ept_enabled();

    this->test_check_control_reserved_properly_set();
    this->test_check_memory_type_reserved();
}

bool
vmcs_ut::list()
{
    this->list_vmcs_intel_x64_cpp();
    this->list_vmcs_intel_x64_h();
    this->list_16bit_control_fields();
    this->list_16bit_guest_state_fields();
    this->list_16bit_host_state_fields();
    this->list_64bit_control_fields();
    this->list_64bit_read_only_data_field();
    this->list_64bit_guest_state_fields();
    this->list_64bit_host_state_fields();
    this->list_32bit_control_fields();
    this->list_32bit_read_only_data_fields();
    this->list_32bit_guest_state_fields();
    this->list_32bit_host_state_field();
    this->list_natural_width_control_fields();
    this->list_natural_width_read_only_data_fields();
    this->list_natural_width_guest_state_fields();
    this->list_natural_width_host_state_fields();

    this->list_checks_on_vmx_controls();
    this->list_checks_on_host_state();
    this->list_checks_on_guest_state();

    this->test_debug_dump();
    this->test_debug_dump_16bit_control_fields();
    this->test_debug_dump_16bit_guest_state_fields();
    this->test_debug_dump_16bit_host_state_fields();
    this->test_debug_dump_64bit_control_fields();
    this->test_debug_dump_64bit_read_only_data_field();
    this->test_debug_dump_64bit_guest_state_fields();
    this->test_debug_dump_64bit_host_state_fields();
    this->test_debug_dump_32bit_control_fields();
    this->test_debug_dump_32bit_read_only_data_fields();
    this->test_debug_dump_32bit_guest_state_fields();
    this->test_debug_dump_32bit_host_state_field();
    this->test_debug_dump_natural_width_control_fields();
    this->test_debug_dump_natural_width_read_only_data_fields();
    this->test_debug_dump_natural_width_guest_state_fields();
    this->test_debug_dump_natural_width_host_state_fields();
    this->test_debug_dump_vmx_controls();
    this->test_debug_dump_pin_based_vm_execution_controls();
    this->test_debug_dump_primary_processor_based_vm_execution_controls();
    this->test_debug_dump_secondary_processor_based_vm_execution_controls();
    this->test_debug_dump_vm_exit_control_fields();
    this->test_debug_dump_vm_entry_control_fields();
    this->test_debug_dump_vmcs_field();
    this->test_debug_dump_vm_control();

    this->test_state();
    this->test_state_segment_registers();
    this->test_state_control_registers();
    this->test_state_debug_registers();
    this->test_state_rflags();
    this->test_state_gdt_base();
    this->test_state_idt_base();
    this->test_state_gdt_limit();
    this->test_state_idt_limit();
    this->test_state_segment_registers_limit();
    this->test_state_segment_registers_access_rights();
    this->test_state_segment_register_base();
    this->test_state_msrs();
    this->test_state_dump();

    this->test_host_vm_state();
    this->test_host_vm_state_segment_registers();
    this->test_host_vm_state_control_registers();
    this->test_host_vm_state_debug_registers();
    this->test_host_vm_state_rflags();
    this->test_host_vm_state_gdt_base();
    this->test_host_vm_state_idt_base();
    this->test_host_vm_state_gdt_limit();
    this->test_host_vm_state_idt_limit();
    this->test_host_vm_state_es_limit();
    this->test_host_vm_state_cs_limit();
    this->test_host_vm_state_ss_limit();
    this->test_host_vm_state_ds_limit();
    this->test_host_vm_state_fs_limit();
    this->test_host_vm_state_gs_limit();
    this->test_host_vm_state_tr_limit();
    this->test_host_vm_state_ldtr_limit();
    this->test_host_vm_state_es_access_rights();
    this->test_host_vm_state_cs_access_rights();
    this->test_host_vm_state_ss_access_rights();
    this->test_host_vm_state_ds_access_rights();
    this->test_host_vm_state_fs_access_rights();
    this->test_host_vm_state_gs_access_rights();
    this->test_host_vm_state_tr_access_rights();
    this->test_host_vm_state_ldtr_access_rights();
    this->test_host_vm_state_es_base();
    this->test_host_vm_state_cs_base();
    this->test_host_vm_state_ss_base();
    this->test_host_vm_state_ds_base();
    this->test_host_vm_state_fs_base();
    this->test_host_vm_state_gs_base();
    this->test_host_vm_state_tr_base();
    this->test_host_vm_state_ldtr_base();
    this->test_host_vm_state_ia32_msrs();
    this->test_host_vm_state_dump();

    this->test_vmm_state_gdt_not_setup();
    this->test_vmm_state_segment_registers();
    this->test_vmm_state_control_registers();
    this->test_vmm_state_rflags();
    this->test_vmm_state_gdt_base();
    this->test_vmm_state_idt_base();
    this->test_vmm_state_gdt_limit();
    this->test_vmm_state_idt_limit();
    this->test_vmm_state_segment_registers_limit();
    this->test_vmm_state_segment_registers_access_rights();
    this->test_vmm_state_segment_registers_base();
    this->test_vmm_state_ia32_efer_msr();
    this->test_vmm_state_dump();

    return true;
}

int
main(int argc, char *argv[])
{
    return RUN_ALL_TESTS(vmcs_ut);
}
