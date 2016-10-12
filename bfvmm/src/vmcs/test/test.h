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
#include <memory_manager/memory_manager.h>

#define run_vmcs_test(cfg, ...) run_vmcs_test_with_args(gsl::cstring_span<>(__PRETTY_FUNCTION__), __LINE__, cfg, __VA_ARGS__)

struct control_flow_path
{
    std::function<void()> setup;
    std::shared_ptr<std::exception> exception;
    bool throws_exception;
};

extern std::map<uint32_t, uint64_t> g_msrs;
extern std::map<uint64_t, uint64_t> g_vmcs_fields;
extern uint8_t span[0x81];
extern bool g_virt_to_phys_return_nullptr;
extern bool g_phys_to_virt_return_nullptr;

void setup_mock(MockRepository &mocks, memory_manager *mm, intrinsics_intel_x64 *in);
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
uint32_t cpuid_eax(uint32_t val);
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
        for (int i = 0; static_cast<size_t>(i) < cfg.size(); i++)
        {
            MockRepository mocks;
            auto mm = mocks.Mock<memory_manager>();
            auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

            setup_mock(mocks, mm, in.get());

            auto path = cfg[static_cast<size_t>(i)];
            path.setup();

            RUN_UNITTEST_WITH_MOCKS(mocks, [&]
            {
                vmcs_intel_x64 vmcs(in);
                auto func = std::bind(std::forward<decltype(mf)>(mf), &vmcs, std::forward<Args>(args)...);

                if (path.throws_exception)
                    this->expect_exception_with_args(func, path.exception, fut, line, i);
                else
                    this->expect_no_exception_with_args(func, fut, line, i);
            });
        }
    }

private:

    void test_constructor_null_intrinsics();
    void test_launch_success();
    void test_launch_vmlaunch_failure();
    void test_launch_create_vmcs_region_failure();
    void test_launch_create_exit_handler_stack_failure();
    void test_launch_clear_failure();
    void test_launch_load_failure();
    void test_promote_failure();
    void test_resume_failure();
    void test_vmread_failure();
    void test_vmwrite_failure();
    void test_vmcs_virtual_processor_identifier();
    void test_vmcs_posted_interrupt_notification_vector();
    void test_vmcs_eptp_index();
    void test_vmcs_guest_es_selector();
    void test_vmcs_guest_cs_selector();
    void test_vmcs_guest_ss_selector();
    void test_vmcs_guest_ds_selector();
    void test_vmcs_guest_fs_selector();
    void test_vmcs_guest_gs_selector();
    void test_vmcs_guest_ldtr_selector();
    void test_vmcs_guest_tr_selector();
    void test_vmcs_guest_interrupt_status();
    void test_vmcs_host_es_selector();
    void test_vmcs_host_cs_selector();
    void test_vmcs_host_ss_selector();
    void test_vmcs_host_ds_selector();
    void test_vmcs_host_fs_selector();
    void test_vmcs_host_gs_selector();
    void test_vmcs_host_tr_selector();
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
