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

#ifndef TEST_H
#define TEST_H

#include <unittest.h>
#include <vector>
#include <functional>
#include <memory>
#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <memory_manager/memory_manager_x64.h>

#define run_vmcs_test(cfg, ...) run_vmcs_test_with_args(gsl::cstring_span<>(__PRETTY_FUNCTION__), __LINE__, cfg, __VA_ARGS__)

struct control_flow_path
{
    std::function<void()> setup;
    std::shared_ptr<std::exception> exception;
    bool throws_exception;
};

struct vm_control;

extern std::map<uint32_t, uint64_t> g_msrs;
extern std::map<uint64_t, uint64_t> g_vmcs_fields;
extern uint8_t span[0x81];
extern bool g_virt_to_phys_return_nullptr;
extern bool g_phys_to_virt_return_nullptr;

void setup_mock(MockRepository &mocks, memory_manager_x64 *mm);
void enable_proc_ctl(uint64_t control);
void enable_proc_ctl2(uint64_t control);
void enable_pin_ctl(uint64_t control);
void enable_exit_ctl(uint64_t control);
void enable_entry_ctl(uint64_t control);
void disable_proc_ctl(uint64_t control);
void disable_proc_ctl2(uint64_t control);
void disable_pin_ctl(uint64_t control);
void disable_exit_ctl(uint64_t control);
void disable_entry_ctl(uint64_t control);
uintptr_t virtptr_to_physint(void *ptr);
void *physint_to_virtptr(uintptr_t phys);

class vmcs_ut : public unittest
{
public:

    vmcs_ut();
    ~vmcs_ut() override = default;

protected:

    bool init() override;
    bool fini() override;
    bool list() override;

    template <typename R, typename ...Args> void
    run_vmcs_test_with_args(gsl::cstring_span<> fut, int line,
                            const std::vector<struct control_flow_path> &cfg,
                            R(vmcs_intel_x64::*mf)(Args...), Args &&... args)
    {
        for (const auto &path : cfg)
        {
            MockRepository mocks;
            auto mm = mocks.Mock<memory_manager_x64>();

            setup_mock(mocks, mm);
            path.setup();

            RUN_UNITTEST_WITH_MOCKS(mocks, [&]
            {
                vmcs_intel_x64 vmcs{};
                auto func = std::bind(std::forward<decltype(mf)>(mf), &vmcs, std::forward<Args>(args)...);

                if (path.throws_exception)
                    this->expect_exception_with_args(std::forward<decltype(func)>(func), path.exception, fut, line);
                else
                    this->expect_no_exception_with_args(std::forward<decltype(func)>(func), fut, line);
            });
        }
    }

    void test_vm_control_with_args(const struct vm_control &ctl, gsl::cstring_span<> fut, int line);

private:

    void test_launch_success();
    void test_launch_vmlaunch_failure();
    void test_launch_create_vmcs_region_failure();
    void test_launch_create_exit_handler_stack_failure();
    void test_launch_clear_failure();
    void test_launch_load_failure();
    void test_promote_failure();
    void test_resume_failure();
    void test_get_vmcs_field();
    void test_get_vmcs_field_if_exists();
    void test_set_vmcs_field();
    void test_set_vmcs_field_if_exists();
    void test_get_vm_control();
    void test_get_vm_control_if_exists();
    void test_set_vm_control();
    void test_set_vm_control_if_allowed();
    void test_vmcs_virtual_processor_identifier();
    void test_vmcs_posted_interrupt_notification_vector();
    void test_vmcs_eptp_index();
    void test_vmcs_guest_es_selector();
    void test_vmcs_guest_es_selector_rpl();
    void test_vmcs_guest_es_selector_ti();
    void test_vmcs_guest_es_selector_index();
    void test_vmcs_guest_cs_selector();
    void test_vmcs_guest_cs_selector_rpl();
    void test_vmcs_guest_cs_selector_ti();
    void test_vmcs_guest_cs_selector_index();
    void test_vmcs_guest_ss_selector();
    void test_vmcs_guest_ss_selector_rpl();
    void test_vmcs_guest_ss_selector_ti();
    void test_vmcs_guest_ss_selector_index();
    void test_vmcs_guest_ds_selector();
    void test_vmcs_guest_ds_selector_rpl();
    void test_vmcs_guest_ds_selector_ti();
    void test_vmcs_guest_ds_selector_index();
    void test_vmcs_guest_fs_selector();
    void test_vmcs_guest_fs_selector_rpl();
    void test_vmcs_guest_fs_selector_ti();
    void test_vmcs_guest_fs_selector_index();
    void test_vmcs_guest_gs_selector();
    void test_vmcs_guest_gs_selector_rpl();
    void test_vmcs_guest_gs_selector_ti();
    void test_vmcs_guest_gs_selector_index();
    void test_vmcs_guest_ldtr_selector();
    void test_vmcs_guest_ldtr_selector_rpl();
    void test_vmcs_guest_ldtr_selector_ti();
    void test_vmcs_guest_ldtr_selector_index();
    void test_vmcs_guest_tr_selector();
    void test_vmcs_guest_tr_selector_rpl();
    void test_vmcs_guest_tr_selector_ti();
    void test_vmcs_guest_tr_selector_index();
    void test_vmcs_guest_interrupt_status();
    void test_vmcs_host_es_selector();
    void test_vmcs_host_es_selector_rpl();
    void test_vmcs_host_es_selector_ti();
    void test_vmcs_host_es_selector_index();
    void test_vmcs_host_cs_selector();
    void test_vmcs_host_cs_selector_rpl();
    void test_vmcs_host_cs_selector_ti();
    void test_vmcs_host_cs_selector_index();
    void test_vmcs_host_ss_selector();
    void test_vmcs_host_ss_selector_rpl();
    void test_vmcs_host_ss_selector_ti();
    void test_vmcs_host_ss_selector_index();
    void test_vmcs_host_ds_selector();
    void test_vmcs_host_ds_selector_rpl();
    void test_vmcs_host_ds_selector_ti();
    void test_vmcs_host_ds_selector_index();
    void test_vmcs_host_fs_selector();
    void test_vmcs_host_fs_selector_rpl();
    void test_vmcs_host_fs_selector_ti();
    void test_vmcs_host_fs_selector_index();
    void test_vmcs_host_gs_selector();
    void test_vmcs_host_gs_selector_rpl();
    void test_vmcs_host_gs_selector_ti();
    void test_vmcs_host_gs_selector_index();
    void test_vmcs_host_tr_selector();
    void test_vmcs_host_tr_selector_rpl();
    void test_vmcs_host_tr_selector_ti();
    void test_vmcs_host_tr_selector_index();
    void test_vmcs_guest_rflags();
    void test_vmcs_guest_rflags_carry_flag();
    void test_vmcs_guest_rflags_parity_flag();
    void test_vmcs_guest_rflags_auxiliary_carry_flag();
    void test_vmcs_guest_rflags_zero_flag();
    void test_vmcs_guest_rflags_sign_flag();
    void test_vmcs_guest_rflags_trap_flag();
    void test_vmcs_guest_rflags_interrupt_enable_flag();
    void test_vmcs_guest_rflags_direction_flag();
    void test_vmcs_guest_rflags_overflow_flag();
    void test_vmcs_guest_rflags_privilege_level();
    void test_vmcs_guest_rflags_nested_task();
    void test_vmcs_guest_rflags_resume_flag();
    void test_vmcs_guest_rflags_virtual_8086_mode();
    void test_vmcs_guest_rflags_alignment_check_access_control();
    void test_vmcs_guest_rflags_virtual_interupt_flag();
    void test_vmcs_guest_rflags_virtual_interupt_pending();
    void test_vmcs_guest_rflags_id_flag();
    void test_vmcs_guest_rflags_reserved();
    void test_vmcs_guest_rflags_always_disabled();
    void test_vmcs_guest_rflags_always_enabled();
    void test_vmcs_guest_cr0();
    void test_vmcs_guest_cr0_protection_enable();
    void test_vmcs_guest_cr0_monitor_coprocessor();
    void test_vmcs_guest_cr0_emulation();
    void test_vmcs_guest_cr0_task_switched();
    void test_vmcs_guest_cr0_extension_type();
    void test_vmcs_guest_cr0_numeric_error();
    void test_vmcs_guest_cr0_write_protect();
    void test_vmcs_guest_cr0_alignment_mask();
    void test_vmcs_guest_cr0_not_write_through();
    void test_vmcs_guest_cr0_cache_disable();
    void test_vmcs_guest_cr0_paging();
    void test_vmcs_guest_cr3();
    void test_vmcs_guest_cr4();
    void test_vmcs_guest_cr4_v8086_mode_extensions();
    void test_vmcs_guest_cr4_protected_mode_virtual_interrupts();
    void test_vmcs_guest_cr4_time_stamp_disable();
    void test_vmcs_guest_cr4_debugging_extensions();
    void test_vmcs_guest_cr4_page_size_extensions();
    void test_vmcs_guest_cr4_physical_address_extensions();
    void test_vmcs_guest_cr4_machine_check_enable();
    void test_vmcs_guest_cr4_page_global_enable();
    void test_vmcs_guest_cr4_performance_monitor_counter_enable();
    void test_vmcs_guest_cr4_osfxsr();
    void test_vmcs_guest_cr4_osxmmexcpt();
    void test_vmcs_guest_cr4_vmx_enable_bit();
    void test_vmcs_guest_cr4_smx_enable_bit();
    void test_vmcs_guest_cr4_fsgsbase_enable_bit();
    void test_vmcs_guest_cr4_pcid_enable_bit();
    void test_vmcs_guest_cr4_osxsave();
    void test_vmcs_guest_cr4_smep_enable_bit();
    void test_vmcs_guest_cr4_smap_enable_bit();
    void test_vmcs_guest_cr4_protection_key_enable_bit();
    void test_vmcs_host_cr0();
    void test_vmcs_host_cr0_protection_enable();
    void test_vmcs_host_cr0_monitor_coprocessor();
    void test_vmcs_host_cr0_emulation();
    void test_vmcs_host_cr0_task_switched();
    void test_vmcs_host_cr0_extension_type();
    void test_vmcs_host_cr0_numeric_error();
    void test_vmcs_host_cr0_write_protect();
    void test_vmcs_host_cr0_alignment_mask();
    void test_vmcs_host_cr0_not_write_through();
    void test_vmcs_host_cr0_cache_disable();
    void test_vmcs_host_cr0_paging();
    void test_vmcs_host_cr3();
    void test_vmcs_host_cr4();
    void test_vmcs_host_cr4_v8086_mode_extensions();
    void test_vmcs_host_cr4_protected_mode_virtual_interrupts();
    void test_vmcs_host_cr4_time_stamp_disable();
    void test_vmcs_host_cr4_debugging_extensions();
    void test_vmcs_host_cr4_page_size_extensions();
    void test_vmcs_host_cr4_physical_address_extensions();
    void test_vmcs_host_cr4_machine_check_enable();
    void test_vmcs_host_cr4_page_global_enable();
    void test_vmcs_host_cr4_performance_monitor_counter_enable();
    void test_vmcs_host_cr4_osfxsr();
    void test_vmcs_host_cr4_osxmmexcpt();
    void test_vmcs_host_cr4_vmx_enable_bit();
    void test_vmcs_host_cr4_smx_enable_bit();
    void test_vmcs_host_cr4_fsgsbase_enable_bit();
    void test_vmcs_host_cr4_pcid_enable_bit();
    void test_vmcs_host_cr4_osxsave();
    void test_vmcs_host_cr4_smep_enable_bit();
    void test_vmcs_host_cr4_smap_enable_bit();
    void test_vmcs_host_cr4_protection_key_enable_bit();
    void test_vmcs_guest_ia32_debugctl();
    void test_vmcs_guest_ia32_debugctl_lbr();
    void test_vmcs_guest_ia32_debugctl_btf();
    void test_vmcs_guest_ia32_debugctl_tr();
    void test_vmcs_guest_ia32_debugctl_bts();
    void test_vmcs_guest_ia32_debugctl_btint();
    void test_vmcs_guest_ia32_debugctl_bt_off_os();
    void test_vmcs_guest_ia32_debugctl_bt_off_user();
    void test_vmcs_guest_ia32_debugctl_freeze_lbrs_on_pmi();
    void test_vmcs_guest_ia32_debugctl_freeze_perfmon_on_pmi();
    void test_vmcs_guest_ia32_debugctl_enable_uncore_pmi();
    void test_vmcs_guest_ia32_debugctl_freeze_while_smm();
    void test_vmcs_guest_ia32_debugctl_rtm_debug();
    void test_vmcs_guest_ia32_debugctl_reserved();
    void test_vmcs_guest_ia32_efer();
    void test_vmcs_guest_ia32_efer_sce();
    void test_vmcs_guest_ia32_efer_lme();
    void test_vmcs_guest_ia32_efer_lma();
    void test_vmcs_guest_ia32_efer_nxe();
    void test_vmcs_guest_ia32_efer_reserved();
    void test_vmcs_host_ia32_efer();
    void test_vmcs_host_ia32_efer_sce();
    void test_vmcs_host_ia32_efer_lme();
    void test_vmcs_host_ia32_efer_lma();
    void test_vmcs_host_ia32_efer_nxe();
    void test_vmcs_host_ia32_efer_reserved();
    void test_vmcs_guest_es_limit();
    void test_vmcs_guest_cs_limit();
    void test_vmcs_guest_ss_limit();
    void test_vmcs_guest_ds_limit();
    void test_vmcs_guest_fs_limit();
    void test_vmcs_guest_gs_limit();
    void test_vmcs_guest_ldtr_limit();
    void test_vmcs_guest_tr_limit();
    void test_vmcs_guest_gdtr_limit();
    void test_vmcs_guest_idtr_limit();
    void test_vmcs_guest_es_access_rights();
    void test_vmcs_guest_es_access_rights_type();
    void test_vmcs_guest_es_access_rights_s();
    void test_vmcs_guest_es_access_rights_dpl();
    void test_vmcs_guest_es_access_rights_present();
    void test_vmcs_guest_es_access_rights_avl();
    void test_vmcs_guest_es_access_rights_l();
    void test_vmcs_guest_es_access_rights_db();
    void test_vmcs_guest_es_access_rights_granularity();
    void test_vmcs_guest_es_access_rights_reserved();
    void test_vmcs_guest_es_access_rights_unusable();
    void test_vmcs_guest_cs_access_rights();
    void test_vmcs_guest_cs_access_rights_type();
    void test_vmcs_guest_cs_access_rights_s();
    void test_vmcs_guest_cs_access_rights_dpl();
    void test_vmcs_guest_cs_access_rights_present();
    void test_vmcs_guest_cs_access_rights_avl();
    void test_vmcs_guest_cs_access_rights_l();
    void test_vmcs_guest_cs_access_rights_db();
    void test_vmcs_guest_cs_access_rights_granularity();
    void test_vmcs_guest_cs_access_rights_reserved();
    void test_vmcs_guest_cs_access_rights_unusable();
    void test_vmcs_guest_ss_access_rights();
    void test_vmcs_guest_ss_access_rights_type();
    void test_vmcs_guest_ss_access_rights_s();
    void test_vmcs_guest_ss_access_rights_dpl();
    void test_vmcs_guest_ss_access_rights_present();
    void test_vmcs_guest_ss_access_rights_avl();
    void test_vmcs_guest_ss_access_rights_l();
    void test_vmcs_guest_ss_access_rights_db();
    void test_vmcs_guest_ss_access_rights_granularity();
    void test_vmcs_guest_ss_access_rights_reserved();
    void test_vmcs_guest_ss_access_rights_unusable();
    void test_vmcs_guest_ds_access_rights();
    void test_vmcs_guest_ds_access_rights_type();
    void test_vmcs_guest_ds_access_rights_s();
    void test_vmcs_guest_ds_access_rights_dpl();
    void test_vmcs_guest_ds_access_rights_present();
    void test_vmcs_guest_ds_access_rights_avl();
    void test_vmcs_guest_ds_access_rights_l();
    void test_vmcs_guest_ds_access_rights_db();
    void test_vmcs_guest_ds_access_rights_granularity();
    void test_vmcs_guest_ds_access_rights_reserved();
    void test_vmcs_guest_ds_access_rights_unusable();
    void test_vmcs_guest_fs_access_rights();
    void test_vmcs_guest_fs_access_rights_type();
    void test_vmcs_guest_fs_access_rights_s();
    void test_vmcs_guest_fs_access_rights_dpl();
    void test_vmcs_guest_fs_access_rights_present();
    void test_vmcs_guest_fs_access_rights_avl();
    void test_vmcs_guest_fs_access_rights_l();
    void test_vmcs_guest_fs_access_rights_db();
    void test_vmcs_guest_fs_access_rights_granularity();
    void test_vmcs_guest_fs_access_rights_reserved();
    void test_vmcs_guest_fs_access_rights_unusable();
    void test_vmcs_guest_gs_access_rights();
    void test_vmcs_guest_gs_access_rights_type();
    void test_vmcs_guest_gs_access_rights_s();
    void test_vmcs_guest_gs_access_rights_dpl();
    void test_vmcs_guest_gs_access_rights_present();
    void test_vmcs_guest_gs_access_rights_avl();
    void test_vmcs_guest_gs_access_rights_l();
    void test_vmcs_guest_gs_access_rights_db();
    void test_vmcs_guest_gs_access_rights_granularity();
    void test_vmcs_guest_gs_access_rights_reserved();
    void test_vmcs_guest_gs_access_rights_unusable();
    void test_vmcs_guest_ldtr_access_rights();
    void test_vmcs_guest_ldtr_access_rights_type();
    void test_vmcs_guest_ldtr_access_rights_s();
    void test_vmcs_guest_ldtr_access_rights_dpl();
    void test_vmcs_guest_ldtr_access_rights_present();
    void test_vmcs_guest_ldtr_access_rights_avl();
    void test_vmcs_guest_ldtr_access_rights_l();
    void test_vmcs_guest_ldtr_access_rights_db();
    void test_vmcs_guest_ldtr_access_rights_granularity();
    void test_vmcs_guest_ldtr_access_rights_reserved();
    void test_vmcs_guest_ldtr_access_rights_unusable();
    void test_vmcs_guest_tr_access_rights();
    void test_vmcs_guest_tr_access_rights_type();
    void test_vmcs_guest_tr_access_rights_s();
    void test_vmcs_guest_tr_access_rights_dpl();
    void test_vmcs_guest_tr_access_rights_present();
    void test_vmcs_guest_tr_access_rights_avl();
    void test_vmcs_guest_tr_access_rights_l();
    void test_vmcs_guest_tr_access_rights_db();
    void test_vmcs_guest_tr_access_rights_granularity();
    void test_vmcs_guest_tr_access_rights_reserved();
    void test_vmcs_guest_tr_access_rights_unusable();
    void test_vmcs_guest_interruptibility_state();
    void test_vmcs_guest_interruptibility_state_blocking_by_sti();
    void test_vmcs_guest_interruptibility_state_blocking_by_mov_ss();
    void test_vmcs_guest_interruptibility_state_blocking_by_smi();
    void test_vmcs_guest_interruptibility_state_blocking_by_nmi();
    void test_vmcs_guest_interruptibility_state_enclave_interruption();
    void test_vmcs_guest_interruptibility_state_reserved();
    void test_vmcs_guest_activity_state();
    void test_vmcs_guest_smbase();
    void test_vmcs_guest_ia32_sysenter_cs();
    void test_vmcs_vmx_preemption_timer_value();
    void test_vmcs_pin_based_vm_execution_controls();
    void test_vmcs_pin_based_vm_execution_controls_external_interrupt_exiting();
    void test_vmcs_pin_based_vm_execution_controls_nmi_exiting();
    void test_vmcs_pin_based_vm_execution_controls_virtual_nmis();
    void test_vmcs_pin_based_vm_execution_controls_activate_vmx_preemption_timer();
    void test_vmcs_pin_based_vm_execution_controls_process_posted_interrupts();
    void test_vmcs_primary_processor_based_vm_execution_controls();
    void test_vmcs_primary_processor_based_vm_execution_controls_interrupt_window_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_use_tsc_offsetting();
    void test_vmcs_primary_processor_based_vm_execution_controls_hlt_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_invlpg_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_mwait_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_rdpmc_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_rdtsc_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_cr3_load_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_cr3_store_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_cr8_load_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_cr8_store_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_use_tpr_shadow();
    void test_vmcs_primary_processor_based_vm_execution_controls_nmi_window_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_mov_dr_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_unconditional_io_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_use_io_bitmaps();
    void test_vmcs_primary_processor_based_vm_execution_controls_monitor_trap_flag();
    void test_vmcs_primary_processor_based_vm_execution_controls_use_msr_bitmaps();
    void test_vmcs_primary_processor_based_vm_execution_controls_monitor_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_pause_exiting();
    void test_vmcs_primary_processor_based_vm_execution_controls_activate_secondary_controls();
    void test_vmcs_exception_bitmap();
    void test_vmcs_page_fault_error_code_mask();
    void test_vmcs_page_fault_error_code_match();
    void test_vmcs_cr3_target_count();
    void test_vmcs_vm_exit_controls();
    void test_vmcs_vm_exit_controls_save_debug_controls();
    void test_vmcs_vm_exit_controls_host_address_space_size();
    void test_vmcs_vm_exit_controls_load_ia32_perf_global_ctrl();
    void test_vmcs_vm_exit_controls_acknowledge_interrupt_on_exit();
    void test_vmcs_vm_exit_controls_save_ia32_pat();
    void test_vmcs_vm_exit_controls_load_ia32_pat();
    void test_vmcs_vm_exit_controls_save_ia32_efer();
    void test_vmcs_vm_exit_controls_load_ia32_efer();
    void test_vmcs_vm_exit_controls_save_vmx_preemption_timer_value();
    void test_vmcs_vm_exit_msr_store_count();
    void test_vmcs_vm_exit_msr_load_count();
    void test_vmcs_vm_entry_controls();
    void test_vmcs_vm_entry_controls_load_debug_controls();
    void test_vmcs_vm_entry_controls_ia_32e_mode_guest();
    void test_vmcs_vm_entry_controls_entry_to_smm();
    void test_vmcs_vm_entry_controls_deactivate_dual_monitor_treatment();
    void test_vmcs_vm_entry_controls_load_ia32_perf_global_ctrl();
    void test_vmcs_vm_entry_controls_load_ia32_pat();
    void test_vmcs_vm_entry_controls_load_ia32_efer();
    void test_vmcs_vm_entry_msr_load_count();
    void test_vmcs_vm_entry_interruption_information_field();
    void test_vmcs_vm_entry_interruption_information_field_vector();
    void test_vmcs_vm_entry_interruption_information_field_type();
    void test_vmcs_vm_entry_interruption_information_field_deliver_error_code_bit();
    void test_vmcs_vm_entry_interruption_information_field_reserved();
    void test_vmcs_vm_entry_interruption_information_field_valid_bit();
    void test_vmcs_vm_entry_exception_error_code();
    void test_vmcs_vm_entry_instruction_length();
    void test_vmcs_tpr_threshold();
    void test_vmcs_secondary_processor_based_vm_execution_controls();
    void test_vmcs_secondary_processor_based_vm_execution_controls_virtualize_apic_accesses();
    void test_vmcs_secondary_processor_based_vm_execution_controls_enable_ept();
    void test_vmcs_secondary_processor_based_vm_execution_controls_descriptor_table_exiting();
    void test_vmcs_secondary_processor_based_vm_execution_controls_enable_rdtscp();
    void test_vmcs_secondary_processor_based_vm_execution_controls_virtualize_x2apic_mode();
    void test_vmcs_secondary_processor_based_vm_execution_controls_enable_vpid();
    void test_vmcs_secondary_processor_based_vm_execution_controls_wbinvd_exiting();
    void test_vmcs_secondary_processor_based_vm_execution_controls_unrestricted_guest();
    void test_vmcs_secondary_processor_based_vm_execution_controls_apic_register_virtualization();
    void test_vmcs_secondary_processor_based_vm_execution_controls_virtual_interrupt_delivery();
    void test_vmcs_secondary_processor_based_vm_execution_controls_pause_loop_exiting();
    void test_vmcs_secondary_processor_based_vm_execution_controls_rdrand_exiting();
    void test_vmcs_secondary_processor_based_vm_execution_controls_enable_invpcid();
    void test_vmcs_secondary_processor_based_vm_execution_controls_enable_vm_functions();
    void test_vmcs_secondary_processor_based_vm_execution_controls_vmcs_shadowing();
    void test_vmcs_secondary_processor_based_vm_execution_controls_rdseed_exiting();
    void test_vmcs_secondary_processor_based_vm_execution_controls_enable_pml();
    void test_vmcs_secondary_processor_based_vm_execution_controls_ept_violation_ve();
    void test_vmcs_secondary_processor_based_vm_execution_controls_enable_xsaves_xrstors();
    void test_vmcs_ple_gap();
    void test_vmcs_ple_window();

    void test_check_vmcs_control_state();
    void test_checks_on_vm_execution_control_fields();
    void test_checks_on_vm_exit_control_fields();
    void test_checks_on_vm_entry_control_fields();
    void test_check_control_ctls_reserved_properly_set();
    void test_check_control_pin_based_ctls_reserved_properly_set();
    void test_check_control_proc_based_ctls_reserved_properly_set();
    void test_check_control_proc_based_ctls2_reserved_properly_set();
    void test_check_control_cr3_count_less_than_4();
    void test_check_control_io_bitmap_address_bits();
    void test_check_control_msr_bitmap_address_bits();
    void test_check_control_tpr_shadow_and_virtual_apic();
    void test_check_control_nmi_exiting_and_virtual_nmi();
    void test_check_control_virtual_nmi_and_nmi_window();
    void test_check_control_virtual_apic_address_bits();
    void test_check_control_x2apic_mode_and_virtual_apic_access();
    void test_check_control_virtual_interrupt_and_external_interrupt();
    void test_check_control_process_posted_interrupt_checks();
    void test_check_control_vpid_checks();
    void test_check_control_enable_ept_checks();
    void test_check_control_enable_pml_checks();
    void test_check_control_unrestricted_guests();
    void test_check_control_enable_vm_functions();
    void test_check_control_enable_vmcs_shadowing();
    void test_check_control_enable_ept_violation_checks();
    void test_check_control_vm_exit_ctls_reserved_properly_set();
    void test_check_control_activate_and_save_preemption_timer_must_be_0();
    void test_check_control_exit_msr_store_address();
    void test_check_control_exit_msr_load_address();
    void test_check_control_vm_entry_ctls_reserved_properly_set();
    void test_check_control_event_injection_type_vector_checks();
    void test_check_control_event_injection_delivery_ec_checks();
    void test_check_control_event_injection_reserved_bits_checks();
    void test_check_control_event_injection_ec_checks();
    void test_check_control_event_injection_instr_length_checks();
    void test_check_control_entry_msr_load_address();

    void test_check_vmcs_host_state();
    void test_check_host_control_registers_and_msrs();
    void test_check_host_segment_and_descriptor_table_registers();
    void test_check_host_checks_related_to_address_space_size();
    void test_check_host_cr0_for_unsupported_bits();
    void test_check_host_cr4_for_unsupported_bits();
    void test_check_host_cr3_for_unsupported_bits();
    void test_check_host_ia32_sysenter_esp_canonical_address();
    void test_check_host_ia32_sysenter_eip_canonical_address();
    void test_check_host_verify_load_ia32_perf_global_ctrl();
    void test_check_host_verify_load_ia32_pat();
    void test_check_host_verify_load_ia32_efer();
    void test_check_host_es_selector_rpl_ti_equal_zero();
    void test_check_host_cs_selector_rpl_ti_equal_zero();
    void test_check_host_ss_selector_rpl_ti_equal_zero();
    void test_check_host_ds_selector_rpl_ti_equal_zero();
    void test_check_host_fs_selector_rpl_ti_equal_zero();
    void test_check_host_gs_selector_rpl_ti_equal_zero();
    void test_check_host_tr_selector_rpl_ti_equal_zero();
    void test_check_host_cs_not_equal_zero();
    void test_check_host_tr_not_equal_zero();
    void test_check_host_ss_not_equal_zero();
    void test_check_host_fs_canonical_base_address();
    void test_check_host_gs_canonical_base_address();
    void test_check_host_gdtr_canonical_base_address();
    void test_check_host_idtr_canonical_base_address();
    void test_check_host_tr_canonical_base_address();
    void test_check_host_if_outside_ia32e_mode();
    void test_check_host_vmcs_host_address_space_size_is_set();
    void test_check_host_host_address_space_disabled();
    void test_check_host_host_address_space_enabled();
};

#endif
