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
    std::shared_ptr<const std::exception> exception;
    bool throws_exception;
};

void setup_mock(MockRepository &mocks, memory_manager *mm, intrinsics_intel_x64 *in);

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
            auto mm = mocks.Mock<memory_manager>();
            auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

            setup_mock(mocks, mm, in.get());
            path.setup();

            RUN_UNITTEST_WITH_MOCKS(mocks, [&]
            {
                vmcs_intel_x64 vmcs(in);
                auto func = std::bind(std::forward<decltype(mf)>(mf), &vmcs, std::forward<Args>(args)...);

                if (path.throws_exception)
                    this->expect_exception_with_args(std::forward<decltype(func)>(func), path.exception, fut, line);
                else
                    this->expect_no_exception_with_args(std::forward<decltype(func)>(func), fut, line);
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
};

#endif
