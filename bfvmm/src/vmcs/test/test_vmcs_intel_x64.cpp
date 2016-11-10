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

#include <gsl/gsl>

#include <test.h>
#include <intrinsics/tss_x64.h>
#include <vmcs/vmcs_intel_x64_resume.h>
#include <vmcs/vmcs_intel_x64_promote.h>
#include <vmcs/vmcs_intel_x64_16bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_16bit_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_16bit_guest_state_fields.h>

#include <intrinsics/rflags_x64.h>
#include <intrinsics/crs_intel_x64.h>
#include <intrinsics/vmx_intel_x64.h>

using namespace x64;
using namespace intel_x64;

extern bool g_vmread_fails;
extern bool g_vmwrite_fails;
extern bool g_vmclear_fails;
extern bool g_vmload_fails;
extern size_t g_new_throws_bad_alloc;

extern void setup_check_vmcs_control_state_paths(std::vector<struct control_flow_path> &cfg);
extern void setup_check_vmcs_guest_state_paths(std::vector<struct control_flow_path> &cfg);
extern void setup_check_vmcs_host_state_paths(std::vector<struct control_flow_path> &cfg);

static struct control_flow_path path;

static void
vmcs_promote_fail(bool state_save)
{
    (void) state_save;
    return;
}

static void
vmcs_resume_fail(state_save_intel_x64 *state_save)
{
    (void) state_save;
    return;
}

static void
setup_check_vmcs_state_paths(std::vector<struct control_flow_path> &cfg)
{
    std::vector<struct control_flow_path> sub_cfg;

    setup_check_vmcs_control_state_paths(sub_cfg);
    setup_check_vmcs_guest_state_paths(sub_cfg);
    setup_check_vmcs_host_state_paths(sub_cfg);

    path.setup = [sub_cfg]
    {
        for (const auto &sub_path : sub_cfg)
            sub_path.setup();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}


static void
setup_launch_success_msrs()
{
    g_msrs[msrs::ia32_vmx_basic::addr] = 0x7FFFFFFUL;
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 0U;
    g_msrs[msrs::ia32_vmx_cr0_fixed1::addr] = 0xffffffffffffffffUL;
    g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 0U;
    g_msrs[msrs::ia32_vmx_cr4_fixed1::addr] = 0xffffffffffffffffUL;

    g_msrs[msrs::ia32_efer::addr] = msrs::ia32_efer::lma::mask;
}

static void
setup_vmcs_x64_state_intrinsics(MockRepository &mocks, vmcs_intel_x64_state *state_in)
{
    mocks.OnCall(state_in, vmcs_intel_x64_state::es).Return(0x10);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs).Return(0x10);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss).Return(0x10);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds).Return(0x10);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs).Return(0x10);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs).Return(0x10);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr).Return(0x10);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr).Return(0x10);

    mocks.OnCall(state_in, vmcs_intel_x64_state::gdt_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::idt_limit).Return(0);

    mocks.OnCall(state_in, vmcs_intel_x64_state::es_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs_limit).Return(0xFFFFFFFF);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss_limit).Return(0xFFFFFFFF);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs_limit).Return(0xFFFFFFFF);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs_limit).Return(0xFFFFFFFF);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr_limit).Return(sizeof(tss_x64));

    mocks.OnCall(state_in, vmcs_intel_x64_state::es_access_rights).Return(access_rights::unusable);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs_access_rights).Return(access_rights::ring0_cs_descriptor);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss_access_rights).Return(access_rights::ring0_ss_descriptor);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_access_rights).Return(access_rights::unusable);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs_access_rights).Return(access_rights::ring0_fs_descriptor);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs_access_rights).Return(access_rights::ring0_gs_descriptor);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr_access_rights).Return(access_rights::unusable);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr_access_rights).Return(access_rights::ring0_tr_descriptor);

    auto cr0 = 0UL;
    cr0 |= cr0::paging::mask;
    cr0 |= cr0::protection_enable::mask;

    auto cr4 = 0UL;
    cr4 |= cr4::physical_address_extensions::mask;

    auto rflags = 0UL;
    rflags |= rflags::always_enabled::mask;
    rflags |= rflags::interrupt_enable_flag::mask;

    mocks.OnCall(state_in, vmcs_intel_x64_state::cr0).Return(cr0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cr3).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cr4).Return(cr4);
    mocks.OnCall(state_in, vmcs_intel_x64_state::dr7).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::rflags).Return(rflags);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gdt_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::idt_base).Return(0);

    mocks.OnCall(state_in, vmcs_intel_x64_state::es_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr_base).Return(0);

    auto efer = 0UL;
    efer |= msrs::ia32_efer::lme::mask;
    efer |= msrs::ia32_efer::lma::mask;

    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_debugctl_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_pat_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_efer_msr).Return(efer);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_perf_global_ctrl_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_cs_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_esp_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_eip_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_fs_base_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_gs_base_msr).Return(0);

    mocks.OnCall(state_in, vmcs_intel_x64_state::dump);
}

static void
setup_vmcs_intrinsics(MockRepository &mocks, memory_manager_x64 *mm)
{
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Do(virtptr_to_physint);
    mocks.OnCall(mm, memory_manager_x64::physint_to_virtptr).Do(physint_to_virtptr);
}

void
vmcs_ut::test_launch_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm);
    setup_vmcs_x64_state_intrinsics(mocks, host_state.get());
    setup_vmcs_x64_state_intrinsics(mocks, guest_state.get());
    setup_launch_success_msrs();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        EXPECT_NO_EXCEPTION(vmcs.launch(host_state, guest_state));
    });
}

void
vmcs_ut::test_launch_vmlaunch_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm);
    setup_vmcs_x64_state_intrinsics(mocks, host_state.get());
    setup_vmcs_x64_state_intrinsics(mocks, guest_state.get());

    mocks.OnCallFunc(__vmwrite).Return(true);
    Call &launch_call = mocks.ExpectCallFunc(__vmlaunch).Return(false);
    mocks.OnCallFunc(__vmwrite).After(launch_call).Do(__vmwrite);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};
        std::vector<struct control_flow_path> cfg;

        setup_check_vmcs_state_paths(cfg);

        for (const auto &sub_path : cfg)
            sub_path.setup();

        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), std::runtime_error);
    });
}

void
vmcs_ut::test_launch_create_vmcs_region_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm);
    setup_vmcs_x64_state_intrinsics(mocks, host_state.get());
    setup_vmcs_x64_state_intrinsics(mocks, guest_state.get());

    auto ___ = gsl::finally([&]
    { g_virt_to_phys_return_nullptr = false; });

    g_virt_to_phys_return_nullptr = true;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};
        this->expect_exception([&]{ vmcs.launch(host_state, guest_state); }, ""_ut_ffe);
    });
}

void
vmcs_ut::test_launch_create_exit_handler_stack_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        auto ___ = gsl::finally([&]
        { g_new_throws_bad_alloc = 0; });

        g_new_throws_bad_alloc = STACK_SIZE * 2;
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), std::bad_alloc);
    });
}

void
vmcs_ut::test_launch_clear_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        auto ___ = gsl::finally([&]
        { g_vmclear_fails = false; });

        g_vmclear_fails = true;
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), std::runtime_error);
    });
}

void
vmcs_ut::test_launch_load_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        auto ___ = gsl::finally([&]
        { g_vmload_fails = false; });

        g_vmload_fails = true;
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), std::runtime_error);
    });
}

void
vmcs_ut::test_promote_failure()
{
    MockRepository mocks;
    mocks.OnCallFunc(vmcs_promote).Do(vmcs_promote_fail);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        EXPECT_EXCEPTION(vmcs.promote(), std::runtime_error);
    });
}

void
vmcs_ut::test_resume_failure()
{
    MockRepository mocks;
    mocks.OnCallFunc(vmcs_resume).Do(vmcs_resume_fail);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        EXPECT_EXCEPTION(vmcs.resume(), std::runtime_error);
    });
}

void
vmcs_ut::test_get_vmcs_field()
{
    std::string name("field");
    std::string what = std::string("get_vmcs_field_failed: ") + name + " field doesn't exist";
    auto exists = true;

    this->expect_exception([&] { get_vmcs_field(0U, name, !exists); }, std::make_shared<std::logic_error>(what));

    g_vmcs_fields[0U] = 42U;

    this->expect_true(get_vmcs_field(0U, name, exists) == 42U);
}

void
vmcs_ut::test_get_vmcs_field_if_exists()
{
    std::string name("field");

    auto exists = true;
    auto verbose = true;
    g_vmcs_fields[0U] = 42U;

    this->expect_true(get_vmcs_field_if_exists(0U, name, verbose, !exists) == 0U);
    this->expect_true(get_vmcs_field_if_exists(0U, name, verbose, exists) == 42U);
}

void
vmcs_ut::test_set_vmcs_field()
{
    std::string name("field");
    std::string what = std::string("set_vmcs_field failed: ") + name + "field doesn't exist";

    auto exists = true;
    g_vmcs_fields[0U] = 0U;
    this->expect_exception([&] { set_vmcs_field(1U, 0U, name, !exists); },
                           std::make_shared<std::logic_error>(what));
    this->expect_true(g_vmcs_fields[0U] == 0U);

    this->expect_no_exception([&] { set_vmcs_field(1U, 0U, name, exists); });
    this->expect_true(g_vmcs_fields[0U] == 1U);
}

void
vmcs_ut::test_set_vmcs_field_if_exists()
{
    std::string name("field");

    auto exists = true;
    auto verbose = true;
    g_vmcs_fields[0U] = 42U;

    this->expect_no_exception([&] { set_vmcs_field_if_exists(0U, 0U, name, !verbose, !exists); });
    this->expect_true(g_vmcs_fields[0U] == 42U);

    this->expect_no_exception([&] { set_vmcs_field_if_exists(0U, 0U, name, verbose, !exists); });
    this->expect_true(g_vmcs_fields[0U] == 42U);

    this->expect_no_exception([&] { set_vmcs_field_if_exists(0U, 0U, name, !verbose, exists); });
    this->expect_true(g_vmcs_fields[0U] == 0U);

    this->expect_no_exception([&] { set_vmcs_field_if_exists(1U, 0U, name, verbose, exists); });
    this->expect_true(g_vmcs_fields[0U] == 1U);
}

void
vmcs_ut::test_get_vm_control()
{
    auto name("control");
    std::string what = std::string("can't get ") + name + ": corresponding vmcs field doesn't exist";

    auto exists = true;
    auto mask = 0x0000000000000002UL;
    g_vmcs_fields[0U] = mask;

    this->expect_exception([&] { get_vm_control(0U, name, mask, !exists); },
                           std::make_shared<std::logic_error>(what));
    this->expect_true(get_vm_control(0U, name, mask, exists) == mask);
}

void
vmcs_ut::test_get_vm_control_if_exists()
{
    auto name("control");
    auto exists = true;
    auto verbose = true;
    auto mask = 0x8UL;
    g_vmcs_fields[0U] = mask;

    this->expect_true(get_vm_control_if_exists(0U, name, mask, verbose, !exists) == 0UL);
    this->expect_true(get_vm_control_if_exists(0U, name, mask, verbose, exists) == mask);
}

void
vmcs_ut::test_set_vm_control()
{
    auto name("control");
    auto exists = true;
    auto mask = 0x0000000000000040UL;
    auto ctls_addr = 0UL;
    auto msr_addr = 0U;

    this->expect_exception([&] { set_vm_control(1UL, msr_addr, ctls_addr, name, mask, !exists); },
                           std::make_shared<std::logic_error>(std::string(name) + "'s corresponding vmcs field doesn't exist"));

    g_msrs[msr_addr] = ~mask;
    this->expect_no_exception([&] { set_vm_control(0UL, msr_addr, ctls_addr, name, mask, exists); });
    this->expect_true((g_vmcs_fields[ctls_addr] & mask) == 0UL);

    g_msrs[msr_addr] = mask;
    this->expect_exception([&] { set_vm_control(0UL, msr_addr, ctls_addr, name, mask, exists); },
                           std::make_shared<std::logic_error>(std::string(name) + " is not allowed to be cleared to 0"));

    g_msrs[msr_addr] = mask << 32;
    this->expect_no_exception([&] { set_vm_control(1UL, msr_addr, ctls_addr, name, mask, exists); });
    this->expect_true((g_vmcs_fields[ctls_addr] & mask) != 0UL);

    g_msrs[msr_addr] = ~(mask << 32);
    this->expect_exception([&] { set_vm_control(1UL, msr_addr, ctls_addr, name, mask, exists); },
                           std::make_shared<std::logic_error>(std::string(name) + " is not allowed to be set to 1"));
}

void
vmcs_ut::test_set_vm_control_if_allowed()
{
    auto name("control");
    auto exists = true;
    auto verbose = true;
    auto mask = 0x0000000000000040UL;
    auto ctls_addr = 0UL;
    auto msr_addr = 0U;

    this->expect_no_exception([&] { set_vm_control_if_allowed(1UL, msr_addr, ctls_addr, name, mask, verbose, !exists); });

    g_vmcs_fields[ctls_addr] = mask;
    g_msrs[msr_addr] = ~mask;

    this->expect_no_exception([&] { set_vm_control_if_allowed(0UL, msr_addr, ctls_addr, name, mask, verbose, exists); });
    this->expect_true((g_vmcs_fields[ctls_addr] & mask) == 0UL);

    g_msrs[msr_addr] = mask;
    this->expect_no_exception([&] { set_vm_control_if_allowed(0UL, msr_addr, ctls_addr, name, mask, verbose, exists); });

    g_msrs[msr_addr] = mask << 32;
    this->expect_no_exception([&] { set_vm_control_if_allowed(1UL, msr_addr, ctls_addr, name, mask, verbose, exists); });
    this->expect_true((g_vmcs_fields[ctls_addr] & mask) != 0UL);

    g_msrs[msr_addr] = ~(mask << 32);
    this->expect_no_exception([&] { set_vm_control_if_allowed(1UL, msr_addr, ctls_addr, name, mask, verbose, exists); });
}

void
vmcs_ut::test_vmcs_virtual_processor_identifier()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::enable_vpid::mask << 32;
    this->expect_true(vmcs::virtual_processor_identifier::exists());

    vmcs::virtual_processor_identifier::set(100UL);
    this->expect_true(vmcs::virtual_processor_identifier::get() == 100UL);

    vmcs::virtual_processor_identifier::set_if_exists(200UL);
    this->expect_true(vmcs::virtual_processor_identifier::get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;
    this->expect_false(vmcs::virtual_processor_identifier::exists());
    this->expect_exception([&] { vmcs::virtual_processor_identifier::set(1UL); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::virtual_processor_identifier::get(); }, ""_ut_lee);
    this->expect_no_exception([&] { vmcs::virtual_processor_identifier::set_if_exists(1UL); });
    this->expect_no_exception([&] { vmcs::virtual_processor_identifier::get_if_exists(); });

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::enable_vpid::mask << 32;
    this->expect_true(vmcs::virtual_processor_identifier::get() == 200UL);
}

void
vmcs_ut::test_vmcs_posted_interrupt_notification_vector()
{
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask << 32;
    this->expect_true(vmcs::posted_interrupt_notification_vector::exists());

    vmcs::posted_interrupt_notification_vector::set(100UL);
    this->expect_true(vmcs::posted_interrupt_notification_vector::get() == 100UL);

    vmcs::posted_interrupt_notification_vector::set_if_exists(200UL);
    this->expect_true(vmcs::posted_interrupt_notification_vector::get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0x0;
    this->expect_false(vmcs::posted_interrupt_notification_vector::exists());
}

void
vmcs_ut::test_vmcs_eptp_index()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask << 32;
    this->expect_true(vmcs::eptp_index::exists());

    vmcs::eptp_index::set(100UL);
    this->expect_true(vmcs::eptp_index::get() == 100UL);

    vmcs::eptp_index::set_if_exists(200UL);
    this->expect_true(vmcs::eptp_index::get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;
    this->expect_false(vmcs::eptp_index::exists());
    this->expect_exception([&] { vmcs::eptp_index::set(1UL); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::eptp_index::get(); }, ""_ut_lee);
    this->expect_no_exception([&] { vmcs::eptp_index::set_if_exists(1UL); });
    this->expect_no_exception([&] { vmcs::eptp_index::get_if_exists(); });

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask << 32;
    this->expect_true(vmcs::eptp_index::get() == 200UL);
}

void
vmcs_ut::test_vmcs_guest_es_selector()
{
    vmcs::guest_es_selector::set(100UL);
    this->expect_true(vmcs::guest_es_selector::get() == 100UL);
    this->expect_true(vmcs::guest_es_selector::exists());

    vmcs::guest_es_selector::set_if_exists(200UL);
    this->expect_true(vmcs::guest_es_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_guest_es_selector_rpl()
{
    vmcs::guest_es_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_es_selector::rpl::get() == 1UL);

    vmcs::guest_es_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_es_selector::rpl::get() == 0UL);

    vmcs::guest_es_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::guest_es_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_es_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_selector_ti()
{
    vmcs::guest_es_selector::ti::set(true);
    this->expect_true(vmcs::guest_es_selector::ti::get());

    vmcs::guest_es_selector::ti::set(false);
    this->expect_false(vmcs::guest_es_selector::ti::get());

    vmcs::guest_es_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::guest_es_selector::ti::get_if_exists());

    vmcs::guest_es_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::guest_es_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_guest_es_selector_index()
{
    vmcs::guest_es_selector::index::set(1UL);
    this->expect_true(vmcs::guest_es_selector::index::get() == 1UL);

    vmcs::guest_es_selector::index::set(0UL);
    this->expect_true(vmcs::guest_es_selector::index::get() == 0UL);

    vmcs::guest_es_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::guest_es_selector::index::get_if_exists() == 1UL);

    vmcs::guest_es_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_selector()
{
    vmcs::guest_cs_selector::set(100UL);

    this->expect_true(vmcs::guest_cs_selector::get() == 100UL);
    this->expect_true(vmcs::guest_cs_selector::exists());

    vmcs::guest_cs_selector::set_if_exists(200UL);
    this->expect_true(vmcs::guest_cs_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_guest_cs_selector_rpl()
{
    vmcs::guest_cs_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_cs_selector::rpl::get() == 1UL);

    vmcs::guest_cs_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_cs_selector::rpl::get() == 0UL);

    vmcs::guest_cs_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::guest_cs_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_cs_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_selector_ti()
{
    vmcs::guest_cs_selector::ti::set(true);
    this->expect_true(vmcs::guest_cs_selector::ti::get());

    vmcs::guest_cs_selector::ti::set(false);
    this->expect_false(vmcs::guest_cs_selector::ti::get());

    vmcs::guest_cs_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::guest_cs_selector::ti::get_if_exists());

    vmcs::guest_cs_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::guest_cs_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cs_selector_index()
{
    vmcs::guest_cs_selector::index::set(1UL);
    this->expect_true(vmcs::guest_cs_selector::index::get() == 1UL);

    vmcs::guest_cs_selector::index::set(0UL);
    this->expect_true(vmcs::guest_cs_selector::index::get() == 0UL);

    vmcs::guest_cs_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::guest_cs_selector::index::get_if_exists() == 1UL);

    vmcs::guest_cs_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_selector()
{
    vmcs::guest_ss_selector::set(100UL);

    this->expect_true(vmcs::guest_ss_selector::get() == 100UL);
    this->expect_true(vmcs::guest_ss_selector::exists());

    vmcs::guest_ss_selector::set_if_exists(200UL);
    this->expect_true(vmcs::guest_ss_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_guest_ss_selector_rpl()
{
    vmcs::guest_ss_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_ss_selector::rpl::get() == 1UL);

    vmcs::guest_ss_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_ss_selector::rpl::get() == 0UL);

    vmcs::guest_ss_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::guest_ss_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_ss_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_selector_ti()
{
    vmcs::guest_ss_selector::ti::set(true);
    this->expect_true(vmcs::guest_ss_selector::ti::get());

    vmcs::guest_ss_selector::ti::set(false);
    this->expect_false(vmcs::guest_ss_selector::ti::get());

    vmcs::guest_ss_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::guest_ss_selector::ti::get_if_exists());

    vmcs::guest_ss_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::guest_ss_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ss_selector_index()
{
    vmcs::guest_ss_selector::index::set(1UL);
    this->expect_true(vmcs::guest_ss_selector::index::get() == 1UL);

    vmcs::guest_ss_selector::index::set(0UL);
    this->expect_true(vmcs::guest_ss_selector::index::get() == 0UL);

    vmcs::guest_ss_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::guest_ss_selector::index::get_if_exists() == 1UL);

    vmcs::guest_ss_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_selector()
{
    vmcs::guest_ds_selector::set(100UL);

    this->expect_true(vmcs::guest_ds_selector::get() == 100UL);
    this->expect_true(vmcs::guest_ds_selector::exists());

    vmcs::guest_ds_selector::set_if_exists(200UL);
    this->expect_true(vmcs::guest_ds_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_guest_ds_selector_rpl()
{
    vmcs::guest_ds_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_ds_selector::rpl::get() == 1UL);

    vmcs::guest_ds_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_ds_selector::rpl::get() == 0UL);

    vmcs::guest_ds_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::guest_ds_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_ds_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_selector_ti()
{
    vmcs::guest_ds_selector::ti::set(true);
    this->expect_true(vmcs::guest_ds_selector::ti::get());

    vmcs::guest_ds_selector::ti::set(false);
    this->expect_false(vmcs::guest_ds_selector::ti::get());

    vmcs::guest_ds_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::guest_ds_selector::ti::get_if_exists());

    vmcs::guest_ds_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::guest_ds_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ds_selector_index()
{
    vmcs::guest_ds_selector::index::set(1UL);
    this->expect_true(vmcs::guest_ds_selector::index::get() == 1UL);

    vmcs::guest_ds_selector::index::set(0UL);
    this->expect_true(vmcs::guest_ds_selector::index::get() == 0UL);

    vmcs::guest_ds_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::guest_ds_selector::index::get_if_exists() == 1UL);

    vmcs::guest_ds_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_selector()
{
    vmcs::guest_fs_selector::set(100UL);

    this->expect_true(vmcs::guest_fs_selector::get() == 100UL);
    this->expect_true(vmcs::guest_fs_selector::exists());

    vmcs::guest_fs_selector::set_if_exists(200UL);
    this->expect_true(vmcs::guest_fs_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_guest_fs_selector_rpl()
{
    vmcs::guest_fs_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_fs_selector::rpl::get() == 1UL);

    vmcs::guest_fs_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_fs_selector::rpl::get() == 0UL);

    vmcs::guest_fs_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::guest_fs_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_fs_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_selector_ti()
{
    vmcs::guest_fs_selector::ti::set(true);
    this->expect_true(vmcs::guest_fs_selector::ti::get());

    vmcs::guest_fs_selector::ti::set(false);
    this->expect_false(vmcs::guest_fs_selector::ti::get());

    vmcs::guest_fs_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::guest_fs_selector::ti::get_if_exists());

    vmcs::guest_fs_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::guest_fs_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_guest_fs_selector_index()
{
    vmcs::guest_fs_selector::index::set(1UL);
    this->expect_true(vmcs::guest_fs_selector::index::get() == 1UL);

    vmcs::guest_fs_selector::index::set(0UL);
    this->expect_true(vmcs::guest_fs_selector::index::get() == 0UL);

    vmcs::guest_fs_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::guest_fs_selector::index::get_if_exists() == 1UL);

    vmcs::guest_fs_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_selector()
{
    vmcs::guest_gs_selector::set(100UL);

    this->expect_true(vmcs::guest_gs_selector::get() == 100UL);
    this->expect_true(vmcs::guest_gs_selector::exists());

    vmcs::guest_gs_selector::set_if_exists(200UL);
    this->expect_true(vmcs::guest_gs_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_guest_gs_selector_rpl()
{
    vmcs::guest_gs_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_gs_selector::rpl::get() == 1UL);

    vmcs::guest_gs_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_gs_selector::rpl::get() == 0UL);

    vmcs::guest_gs_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::guest_gs_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_gs_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_selector_ti()
{
    vmcs::guest_gs_selector::ti::set(true);
    this->expect_true(vmcs::guest_gs_selector::ti::get());

    vmcs::guest_gs_selector::ti::set(false);
    this->expect_false(vmcs::guest_gs_selector::ti::get());

    vmcs::guest_gs_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::guest_gs_selector::ti::get_if_exists());

    vmcs::guest_gs_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::guest_gs_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_guest_gs_selector_index()
{
    vmcs::guest_gs_selector::index::set(1UL);
    this->expect_true(vmcs::guest_gs_selector::index::get() == 1UL);

    vmcs::guest_gs_selector::index::set(0UL);
    this->expect_true(vmcs::guest_gs_selector::index::get() == 0UL);

    vmcs::guest_gs_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::guest_gs_selector::index::get_if_exists() == 1UL);

    vmcs::guest_gs_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_selector()
{
    vmcs::guest_ldtr_selector::set(100UL);

    this->expect_true(vmcs::guest_ldtr_selector::get() == 100UL);
    this->expect_true(vmcs::guest_ldtr_selector::exists());

    vmcs::guest_ldtr_selector::set_if_exists(200UL);
    this->expect_true(vmcs::guest_ldtr_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_selector_rpl()
{
    vmcs::guest_ldtr_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_ldtr_selector::rpl::get() == 1UL);

    vmcs::guest_ldtr_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_ldtr_selector::rpl::get() == 0UL);

    vmcs::guest_ldtr_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::guest_ldtr_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_ldtr_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_selector_ti()
{
    vmcs::guest_ldtr_selector::ti::set(true);
    this->expect_true(vmcs::guest_ldtr_selector::ti::get());

    vmcs::guest_ldtr_selector::ti::set(false);
    this->expect_false(vmcs::guest_ldtr_selector::ti::get());

    vmcs::guest_ldtr_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::guest_ldtr_selector::ti::get_if_exists());

    vmcs::guest_ldtr_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::guest_ldtr_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ldtr_selector_index()
{
    vmcs::guest_ldtr_selector::index::set(1UL);
    this->expect_true(vmcs::guest_ldtr_selector::index::get() == 1UL);

    vmcs::guest_ldtr_selector::index::set(0UL);
    this->expect_true(vmcs::guest_ldtr_selector::index::get() == 0UL);

    vmcs::guest_ldtr_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::guest_ldtr_selector::index::get_if_exists() == 1UL);

    vmcs::guest_ldtr_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_selector()
{
    vmcs::guest_tr_selector::set(100UL);

    this->expect_true(vmcs::guest_tr_selector::get() == 100UL);
    this->expect_true(vmcs::guest_tr_selector::exists());

    vmcs::guest_tr_selector::set_if_exists(200UL);
    this->expect_true(vmcs::guest_tr_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_guest_tr_selector_rpl()
{
    vmcs::guest_tr_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_tr_selector::rpl::get() == 1UL);

    vmcs::guest_tr_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_tr_selector::rpl::get() == 0UL);

    vmcs::guest_tr_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::guest_tr_selector::rpl::get_if_exists() == 1UL);

    vmcs::guest_tr_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_selector_ti()
{
    vmcs::guest_tr_selector::ti::set(true);
    this->expect_true(vmcs::guest_tr_selector::ti::get());

    vmcs::guest_tr_selector::ti::set(false);
    this->expect_false(vmcs::guest_tr_selector::ti::get());

    vmcs::guest_tr_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::guest_tr_selector::ti::get_if_exists());

    vmcs::guest_tr_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::guest_tr_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_guest_tr_selector_index()
{
    vmcs::guest_tr_selector::index::set(1UL);
    this->expect_true(vmcs::guest_tr_selector::index::get() == 1UL);

    vmcs::guest_tr_selector::index::set(0UL);
    this->expect_true(vmcs::guest_tr_selector::index::get() == 0UL);

    vmcs::guest_tr_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::guest_tr_selector::index::get_if_exists() == 1UL);

    vmcs::guest_tr_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_interrupt_status()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask << 32;

    this->expect_true(vmcs::guest_interrupt_status::exists());

    vmcs::guest_interrupt_status::set(100UL);
    this->expect_true(vmcs::guest_interrupt_status::get() == 100UL);

    vmcs::guest_interrupt_status::set_if_exists(200UL);
    this->expect_true(vmcs::guest_interrupt_status::get_if_exists() == 200UL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;
    this->expect_false(vmcs::guest_interrupt_status::exists());
    this->expect_exception([&] { vmcs::guest_interrupt_status::set(1UL); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::guest_interrupt_status::get(); }, ""_ut_lee);
    this->expect_no_exception([&] { vmcs::guest_interrupt_status::set_if_exists(1UL); });
    this->expect_no_exception([&] { vmcs::guest_interrupt_status::get_if_exists(); });
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask << 32;
    this->expect_true(vmcs::guest_interrupt_status::get() == 200UL);
}

void
vmcs_ut::test_vmcs_host_es_selector()
{
    vmcs::host_es_selector::set(100UL);

    this->expect_true(vmcs::host_es_selector::get() == 100UL);
    this->expect_true(vmcs::host_es_selector::exists());

    vmcs::host_es_selector::set_if_exists(200UL);

    this->expect_true(vmcs::host_es_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_host_es_selector_rpl()
{
    vmcs::host_es_selector::rpl::set(1UL);
    this->expect_true(vmcs::host_es_selector::rpl::get() == 1UL);

    vmcs::host_es_selector::rpl::set(0UL);
    this->expect_true(vmcs::host_es_selector::rpl::get() == 0UL);

    vmcs::host_es_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::host_es_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_es_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::host_es_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_es_selector_ti()
{
    vmcs::host_es_selector::ti::set(true);
    this->expect_true(vmcs::host_es_selector::ti::get());

    vmcs::host_es_selector::ti::set(false);
    this->expect_false(vmcs::host_es_selector::ti::get());

    vmcs::host_es_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::host_es_selector::ti::get_if_exists());

    vmcs::host_es_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::host_es_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_host_es_selector_index()
{
    vmcs::host_es_selector::index::set(1UL);
    this->expect_true(vmcs::host_es_selector::index::get() == 1UL);

    vmcs::host_es_selector::index::set(0UL);
    this->expect_true(vmcs::host_es_selector::index::get() == 0UL);

    vmcs::host_es_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::host_es_selector::index::get_if_exists() == 1UL);

    vmcs::host_es_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::host_es_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_cs_selector()
{
    vmcs::host_cs_selector::set(100UL);

    this->expect_true(vmcs::host_cs_selector::get() == 100UL);
    this->expect_true(vmcs::host_cs_selector::exists());

    vmcs::host_cs_selector::set_if_exists(200UL);

    this->expect_true(vmcs::host_cs_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_host_cs_selector_rpl()
{
    vmcs::host_cs_selector::rpl::set(1UL);
    this->expect_true(vmcs::host_cs_selector::rpl::get() == 1UL);

    vmcs::host_cs_selector::rpl::set(0UL);
    this->expect_true(vmcs::host_cs_selector::rpl::get() == 0UL);

    vmcs::host_cs_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::host_cs_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_cs_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::host_cs_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_cs_selector_ti()
{
    vmcs::host_cs_selector::ti::set(true);
    this->expect_true(vmcs::host_cs_selector::ti::get());

    vmcs::host_cs_selector::ti::set(false);
    this->expect_false(vmcs::host_cs_selector::ti::get());

    vmcs::host_cs_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::host_cs_selector::ti::get_if_exists());

    vmcs::host_cs_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::host_cs_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_host_cs_selector_index()
{
    vmcs::host_cs_selector::index::set(1UL);
    this->expect_true(vmcs::host_cs_selector::index::get() == 1UL);

    vmcs::host_cs_selector::index::set(0UL);
    this->expect_true(vmcs::host_cs_selector::index::get() == 0UL);

    vmcs::host_cs_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::host_cs_selector::index::get_if_exists() == 1UL);

    vmcs::host_cs_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::host_cs_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ss_selector()
{
    vmcs::host_ss_selector::set(100UL);

    this->expect_true(vmcs::host_ss_selector::get() == 100UL);
    this->expect_true(vmcs::host_ss_selector::exists());

    vmcs::host_ss_selector::set_if_exists(200UL);

    this->expect_true(vmcs::host_ss_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_host_ss_selector_rpl()
{
    vmcs::host_ss_selector::rpl::set(1UL);
    this->expect_true(vmcs::host_ss_selector::rpl::get() == 1UL);

    vmcs::host_ss_selector::rpl::set(0UL);
    this->expect_true(vmcs::host_ss_selector::rpl::get() == 0UL);

    vmcs::host_ss_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::host_ss_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_ss_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::host_ss_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ss_selector_ti()
{
    vmcs::host_ss_selector::ti::set(true);
    this->expect_true(vmcs::host_ss_selector::ti::get());

    vmcs::host_ss_selector::ti::set(false);
    this->expect_false(vmcs::host_ss_selector::ti::get());

    vmcs::host_ss_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::host_ss_selector::ti::get_if_exists());

    vmcs::host_ss_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::host_ss_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_host_ss_selector_index()
{
    vmcs::host_ss_selector::index::set(1UL);
    this->expect_true(vmcs::host_ss_selector::index::get() == 1UL);

    vmcs::host_ss_selector::index::set(0UL);
    this->expect_true(vmcs::host_ss_selector::index::get() == 0UL);

    vmcs::host_ss_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::host_ss_selector::index::get_if_exists() == 1UL);

    vmcs::host_ss_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::host_ss_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ds_selector()
{
    vmcs::host_ds_selector::set(100UL);

    this->expect_true(vmcs::host_ds_selector::get() == 100UL);
    this->expect_true(vmcs::host_ds_selector::exists());

    vmcs::host_ds_selector::set_if_exists(200UL);

    this->expect_true(vmcs::host_ds_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_host_ds_selector_rpl()
{
    vmcs::host_ds_selector::rpl::set(1UL);
    this->expect_true(vmcs::host_ds_selector::rpl::get() == 1UL);

    vmcs::host_ds_selector::rpl::set(0UL);
    this->expect_true(vmcs::host_ds_selector::rpl::get() == 0UL);

    vmcs::host_ds_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::host_ds_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_ds_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::host_ds_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ds_selector_ti()
{
    vmcs::host_ds_selector::ti::set(true);
    this->expect_true(vmcs::host_ds_selector::ti::get());

    vmcs::host_ds_selector::ti::set(false);
    this->expect_false(vmcs::host_ds_selector::ti::get());

    vmcs::host_ds_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::host_ds_selector::ti::get_if_exists());

    vmcs::host_ds_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::host_ds_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_host_ds_selector_index()
{
    vmcs::host_ds_selector::index::set(1UL);
    this->expect_true(vmcs::host_ds_selector::index::get() == 1UL);

    vmcs::host_ds_selector::index::set(0UL);
    this->expect_true(vmcs::host_ds_selector::index::get() == 0UL);

    vmcs::host_ds_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::host_ds_selector::index::get_if_exists() == 1UL);

    vmcs::host_ds_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::host_ds_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_fs_selector()
{
    vmcs::host_fs_selector::set(100UL);

    this->expect_true(vmcs::host_fs_selector::get() == 100UL);
    this->expect_true(vmcs::host_fs_selector::exists());

    vmcs::host_fs_selector::set_if_exists(200UL);

    this->expect_true(vmcs::host_fs_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_host_fs_selector_rpl()
{
    vmcs::host_fs_selector::rpl::set(1UL);
    this->expect_true(vmcs::host_fs_selector::rpl::get() == 1UL);

    vmcs::host_fs_selector::rpl::set(0UL);
    this->expect_true(vmcs::host_fs_selector::rpl::get() == 0UL);

    vmcs::host_fs_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::host_fs_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_fs_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::host_fs_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_fs_selector_ti()
{
    vmcs::host_fs_selector::ti::set(true);
    this->expect_true(vmcs::host_fs_selector::ti::get());

    vmcs::host_fs_selector::ti::set(false);
    this->expect_false(vmcs::host_fs_selector::ti::get());

    vmcs::host_fs_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::host_fs_selector::ti::get_if_exists());

    vmcs::host_fs_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::host_fs_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_host_fs_selector_index()
{
    vmcs::host_fs_selector::index::set(1UL);
    this->expect_true(vmcs::host_fs_selector::index::get() == 1UL);

    vmcs::host_fs_selector::index::set(0UL);
    this->expect_true(vmcs::host_fs_selector::index::get() == 0UL);

    vmcs::host_fs_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::host_fs_selector::index::get_if_exists() == 1UL);

    vmcs::host_fs_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::host_fs_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_gs_selector()
{
    vmcs::host_gs_selector::set(100UL);

    this->expect_true(vmcs::host_gs_selector::get() == 100UL);
    this->expect_true(vmcs::host_gs_selector::exists());

    vmcs::host_gs_selector::set_if_exists(200UL);

    this->expect_true(vmcs::host_gs_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_host_gs_selector_rpl()
{
    vmcs::host_gs_selector::rpl::set(1UL);
    this->expect_true(vmcs::host_gs_selector::rpl::get() == 1UL);

    vmcs::host_gs_selector::rpl::set(0UL);
    this->expect_true(vmcs::host_gs_selector::rpl::get() == 0UL);

    vmcs::host_gs_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::host_gs_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_gs_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::host_gs_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_gs_selector_ti()
{
    vmcs::host_gs_selector::ti::set(true);
    this->expect_true(vmcs::host_gs_selector::ti::get());

    vmcs::host_gs_selector::ti::set(false);
    this->expect_false(vmcs::host_gs_selector::ti::get());

    vmcs::host_gs_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::host_gs_selector::ti::get_if_exists());

    vmcs::host_gs_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::host_gs_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_host_gs_selector_index()
{
    vmcs::host_gs_selector::index::set(1UL);
    this->expect_true(vmcs::host_gs_selector::index::get() == 1UL);

    vmcs::host_gs_selector::index::set(0UL);
    this->expect_true(vmcs::host_gs_selector::index::get() == 0UL);

    vmcs::host_gs_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::host_gs_selector::index::get_if_exists() == 1UL);

    vmcs::host_gs_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::host_gs_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_tr_selector()
{
    vmcs::host_tr_selector::set(100UL);

    this->expect_true(vmcs::host_tr_selector::get() == 100UL);
    this->expect_true(vmcs::host_tr_selector::exists());

    vmcs::host_tr_selector::set_if_exists(200UL);

    this->expect_true(vmcs::host_tr_selector::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_host_tr_selector_rpl()
{
    vmcs::host_tr_selector::rpl::set(1UL);
    this->expect_true(vmcs::host_tr_selector::rpl::get() == 1UL);

    vmcs::host_tr_selector::rpl::set(0UL);
    this->expect_true(vmcs::host_tr_selector::rpl::get() == 0UL);

    vmcs::host_tr_selector::rpl::set_if_exists(1UL);
    this->expect_true(vmcs::host_tr_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_tr_selector::rpl::set_if_exists(0UL);
    this->expect_true(vmcs::host_tr_selector::rpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_tr_selector_ti()
{
    vmcs::host_tr_selector::ti::set(true);
    this->expect_true(vmcs::host_tr_selector::ti::get());

    vmcs::host_tr_selector::ti::set(false);
    this->expect_false(vmcs::host_tr_selector::ti::get());

    vmcs::host_tr_selector::ti::set_if_exists(true);
    this->expect_true(vmcs::host_tr_selector::ti::get_if_exists());

    vmcs::host_tr_selector::ti::set_if_exists(false);
    this->expect_false(vmcs::host_tr_selector::ti::get_if_exists());
}

void
vmcs_ut::test_vmcs_host_tr_selector_index()
{
    vmcs::host_tr_selector::index::set(1UL);
    this->expect_true(vmcs::host_tr_selector::index::get() == 1UL);

    vmcs::host_tr_selector::index::set(0UL);
    this->expect_true(vmcs::host_tr_selector::index::get() == 0UL);

    vmcs::host_tr_selector::index::set_if_exists(1UL);
    this->expect_true(vmcs::host_tr_selector::index::get_if_exists() == 1UL);

    vmcs::host_tr_selector::index::set_if_exists(0UL);
    this->expect_true(vmcs::host_tr_selector::index::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags()
{
    vmcs::guest_rflags::set(100UL);

    this->expect_true(vmcs::guest_rflags::get() == 100UL);
    this->expect_true(vmcs::guest_rflags::exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_carry_flag()
{
    vmcs::guest_rflags::carry_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::carry_flag::get() == 1UL);

    vmcs::guest_rflags::carry_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::carry_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_parity_flag()
{
    vmcs::guest_rflags::parity_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::parity_flag::get() == 1UL);

    vmcs::guest_rflags::parity_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::parity_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_auxiliary_carry_flag()
{
    vmcs::guest_rflags::auxiliary_carry_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::auxiliary_carry_flag::get() == 1UL);

    vmcs::guest_rflags::auxiliary_carry_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::auxiliary_carry_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_zero_flag()
{
    vmcs::guest_rflags::zero_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::zero_flag::get() == 1UL);

    vmcs::guest_rflags::zero_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::zero_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_sign_flag()
{
    vmcs::guest_rflags::sign_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::sign_flag::get() == 1UL);

    vmcs::guest_rflags::sign_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::sign_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_trap_flag()
{
    vmcs::guest_rflags::trap_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::trap_flag::get() == 1UL);

    vmcs::guest_rflags::trap_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::trap_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_interrupt_enable_flag()
{
    vmcs::guest_rflags::interrupt_enable_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::interrupt_enable_flag::get() == 1UL);

    vmcs::guest_rflags::interrupt_enable_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::interrupt_enable_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_direction_flag()
{
    vmcs::guest_rflags::direction_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::direction_flag::get() == 1UL);

    vmcs::guest_rflags::direction_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::direction_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_overflow_flag()
{
    vmcs::guest_rflags::overflow_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::overflow_flag::get() == 1UL);

    vmcs::guest_rflags::overflow_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::overflow_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_privilege_level()
{
    vmcs::guest_rflags::privilege_level::set(1UL);
    this->expect_true(vmcs::guest_rflags::privilege_level::get() == 1UL);

    vmcs::guest_rflags::privilege_level::set(2UL);
    this->expect_true(vmcs::guest_rflags::privilege_level::get() == 2UL);

    vmcs::guest_rflags::privilege_level::set(3UL);
    this->expect_true(vmcs::guest_rflags::privilege_level::get() == 3UL);

    vmcs::guest_rflags::privilege_level::set(0UL);
    this->expect_true(vmcs::guest_rflags::privilege_level::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_nested_task()
{
    vmcs::guest_rflags::nested_task::set(1UL);
    this->expect_true(vmcs::guest_rflags::nested_task::get() == 1UL);

    vmcs::guest_rflags::nested_task::set(0UL);
    this->expect_true(vmcs::guest_rflags::nested_task::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_resume_flag()
{
    vmcs::guest_rflags::resume_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::resume_flag::get() == 1UL);

    vmcs::guest_rflags::resume_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::resume_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_virtual_8086_mode()
{
    vmcs::guest_rflags::virtual_8086_mode::set(1UL);
    this->expect_true(vmcs::guest_rflags::virtual_8086_mode::get() == 1UL);

    vmcs::guest_rflags::virtual_8086_mode::set(0UL);
    this->expect_true(vmcs::guest_rflags::virtual_8086_mode::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_alignment_check_access_control()
{
    vmcs::guest_rflags::alignment_check_access_control::set(1UL);
    this->expect_true(vmcs::guest_rflags::alignment_check_access_control::get() == 1UL);

    vmcs::guest_rflags::alignment_check_access_control::set(0UL);
    this->expect_true(vmcs::guest_rflags::alignment_check_access_control::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_virtual_interupt_flag()
{
    vmcs::guest_rflags::virtual_interupt_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::virtual_interupt_flag::get() == 1UL);

    vmcs::guest_rflags::virtual_interupt_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::virtual_interupt_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_virtual_interupt_pending()
{
    vmcs::guest_rflags::virtual_interupt_pending::set(1UL);
    this->expect_true(vmcs::guest_rflags::virtual_interupt_pending::get() == 1UL);

    vmcs::guest_rflags::virtual_interupt_pending::set(0UL);
    this->expect_true(vmcs::guest_rflags::virtual_interupt_pending::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_id_flag()
{
    vmcs::guest_rflags::id_flag::set(1UL);
    this->expect_true(vmcs::guest_rflags::id_flag::get() == 1UL);

    vmcs::guest_rflags::id_flag::set(0UL);
    this->expect_true(vmcs::guest_rflags::id_flag::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_reserved()
{
    vmcs::guest_rflags::reserved::set(0x100000000UL);
    this->expect_true(vmcs::guest_rflags::reserved::get() == 0x100000000UL);

    vmcs::guest_rflags::reserved::set(0UL);
    this->expect_true(vmcs::guest_rflags::reserved::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_always_disabled()
{
    vmcs::guest_rflags::always_disabled::set(0x100000000UL);
    this->expect_true(vmcs::guest_rflags::always_disabled::get() == 0x100000000UL);

    vmcs::guest_rflags::always_disabled::set(0UL);
    this->expect_true(vmcs::guest_rflags::always_disabled::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_always_enabled()
{
    vmcs::guest_rflags::always_enabled::set(2UL);
    this->expect_true(vmcs::guest_rflags::always_enabled::get() == 2UL);

    vmcs::guest_rflags::always_enabled::set(0UL);
    this->expect_true(vmcs::guest_rflags::always_enabled::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cr0()
{
    vmcs::guest_cr0::set(0xFFFFFFFFU);
    this->expect_true(vmcs::guest_cr0::get() == 0xFFFFFFFFU);

    vmcs::guest_cr0::dump();
}

void
vmcs_ut::test_vmcs_guest_cr0_protection_enable()
{
    vmcs::guest_cr0::protection_enable::set(1UL);
    this->expect_true(vmcs::guest_cr0::protection_enable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr0_monitor_coprocessor()
{
    vmcs::guest_cr0::monitor_coprocessor::set(1UL);
    this->expect_true(vmcs::guest_cr0::monitor_coprocessor::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr0_emulation()
{
    vmcs::guest_cr0::emulation::set(1UL);
    this->expect_true(vmcs::guest_cr0::emulation::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr0_task_switched()
{
    vmcs::guest_cr0::task_switched::set(1UL);
    this->expect_true(vmcs::guest_cr0::task_switched::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr0_extension_type()
{
    vmcs::guest_cr0::extension_type::set(1UL);
    this->expect_true(vmcs::guest_cr0::extension_type::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr0_numeric_error()
{
    vmcs::guest_cr0::numeric_error::set(1UL);
    this->expect_true(vmcs::guest_cr0::numeric_error::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr0_write_protect()
{
    vmcs::guest_cr0::write_protect::set(1UL);
    this->expect_true(vmcs::guest_cr0::write_protect::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr0_alignment_mask()
{
    vmcs::guest_cr0::alignment_mask::set(1UL);
    this->expect_true(vmcs::guest_cr0::alignment_mask::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr0_not_write_through()
{
    vmcs::guest_cr0::not_write_through::set(1UL);
    this->expect_true(vmcs::guest_cr0::not_write_through::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr0_cache_disable()
{
    vmcs::guest_cr0::cache_disable::set(1UL);
    this->expect_true(vmcs::guest_cr0::cache_disable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr0_paging()
{
    vmcs::guest_cr0::paging::set(1UL);
    this->expect_true(vmcs::guest_cr0::paging::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr3()
{
    vmcs::guest_cr3::set(100UL);
    this->expect_true(vmcs::guest_cr3::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_cr4()
{
    vmcs::guest_cr4::set(0xFFFFFFFFU);
    this->expect_true(vmcs::guest_cr4::get() == 0xFFFFFFFFU);

    vmcs::guest_cr4::dump();
}

void
vmcs_ut::test_vmcs_guest_cr4_v8086_mode_extensions()
{
    vmcs::guest_cr4::v8086_mode_extensions::set(1UL);
    this->expect_true(vmcs::guest_cr4::v8086_mode_extensions::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_protected_mode_virtual_interrupts()
{
    vmcs::guest_cr4::protected_mode_virtual_interrupts::set(1UL);
    this->expect_true(vmcs::guest_cr4::protected_mode_virtual_interrupts::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_time_stamp_disable()
{
    vmcs::guest_cr4::time_stamp_disable::set(1UL);
    this->expect_true(vmcs::guest_cr4::time_stamp_disable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_debugging_extensions()
{
    vmcs::guest_cr4::debugging_extensions::set(1UL);
    this->expect_true(vmcs::guest_cr4::debugging_extensions::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_page_size_extensions()
{
    vmcs::guest_cr4::page_size_extensions::set(1UL);
    this->expect_true(vmcs::guest_cr4::page_size_extensions::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_physical_address_extensions()
{
    vmcs::guest_cr4::physical_address_extensions::set(1UL);
    this->expect_true(vmcs::guest_cr4::physical_address_extensions::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_machine_check_enable()
{
    vmcs::guest_cr4::machine_check_enable::set(1UL);
    this->expect_true(vmcs::guest_cr4::machine_check_enable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_page_global_enable()
{
    vmcs::guest_cr4::page_global_enable::set(1UL);
    this->expect_true(vmcs::guest_cr4::page_global_enable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_performance_monitor_counter_enable()
{
    vmcs::guest_cr4::performance_monitor_counter_enable::set(1UL);
    this->expect_true(vmcs::guest_cr4::performance_monitor_counter_enable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_osfxsr()
{
    vmcs::guest_cr4::osfxsr::set(1UL);
    this->expect_true(vmcs::guest_cr4::osfxsr::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_osxmmexcpt()
{
    vmcs::guest_cr4::osxmmexcpt::set(1UL);
    this->expect_true(vmcs::guest_cr4::osxmmexcpt::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_vmx_enable_bit()
{
    vmcs::guest_cr4::vmx_enable_bit::set(1UL);
    this->expect_true(vmcs::guest_cr4::vmx_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_smx_enable_bit()
{
    vmcs::guest_cr4::smx_enable_bit::set(1UL);
    this->expect_true(vmcs::guest_cr4::smx_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_fsgsbase_enable_bit()
{
    vmcs::guest_cr4::fsgsbase_enable_bit::set(1UL);
    this->expect_true(vmcs::guest_cr4::fsgsbase_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_pcid_enable_bit()
{
    vmcs::guest_cr4::pcid_enable_bit::set(1UL);
    this->expect_true(vmcs::guest_cr4::pcid_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_osxsave()
{
    vmcs::guest_cr4::osxsave::set(1UL);
    this->expect_true(vmcs::guest_cr4::osxsave::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_smep_enable_bit()
{
    vmcs::guest_cr4::smep_enable_bit::set(1UL);
    this->expect_true(vmcs::guest_cr4::smep_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_smap_enable_bit()
{
    vmcs::guest_cr4::smap_enable_bit::set(1UL);
    this->expect_true(vmcs::guest_cr4::smap_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cr4_protection_key_enable_bit()
{
    vmcs::guest_cr4::protection_key_enable_bit::set(1UL);
    this->expect_true(vmcs::guest_cr4::protection_key_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0()
{
    vmcs::host_cr0::set(0xFFFFFFFFU);
    this->expect_true(vmcs::host_cr0::get() == 0xFFFFFFFFU);

    vmcs::host_cr0::dump();
}

void
vmcs_ut::test_vmcs_host_cr0_protection_enable()
{
    vmcs::host_cr0::protection_enable::set(1UL);
    this->expect_true(vmcs::host_cr0::protection_enable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0_monitor_coprocessor()
{
    vmcs::host_cr0::monitor_coprocessor::set(1UL);
    this->expect_true(vmcs::host_cr0::monitor_coprocessor::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0_emulation()
{
    vmcs::host_cr0::emulation::set(1UL);
    this->expect_true(vmcs::host_cr0::emulation::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0_task_switched()
{
    vmcs::host_cr0::task_switched::set(1UL);
    this->expect_true(vmcs::host_cr0::task_switched::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0_extension_type()
{
    vmcs::host_cr0::extension_type::set(1UL);
    this->expect_true(vmcs::host_cr0::extension_type::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0_numeric_error()
{
    vmcs::host_cr0::numeric_error::set(1UL);
    this->expect_true(vmcs::host_cr0::numeric_error::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0_write_protect()
{
    vmcs::host_cr0::write_protect::set(1UL);
    this->expect_true(vmcs::host_cr0::write_protect::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0_alignment_mask()
{
    vmcs::host_cr0::alignment_mask::set(1UL);
    this->expect_true(vmcs::host_cr0::alignment_mask::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0_not_write_through()
{
    vmcs::host_cr0::not_write_through::set(1UL);
    this->expect_true(vmcs::host_cr0::not_write_through::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0_cache_disable()
{
    vmcs::host_cr0::cache_disable::set(1UL);
    this->expect_true(vmcs::host_cr0::cache_disable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr0_paging()
{
    vmcs::host_cr0::paging::set(1UL);
    this->expect_true(vmcs::host_cr0::paging::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr3()
{
    vmcs::host_cr3::set(100UL);
    this->expect_true(vmcs::host_cr3::get() == 100UL);
}

void
vmcs_ut::test_vmcs_host_cr4()
{
    vmcs::host_cr4::set(0xFFFFFFFFU);
    this->expect_true(vmcs::host_cr4::get() == 0xFFFFFFFFU);

    vmcs::host_cr4::dump();
}

void
vmcs_ut::test_vmcs_host_cr4_v8086_mode_extensions()
{
    vmcs::host_cr4::v8086_mode_extensions::set(1UL);
    this->expect_true(vmcs::host_cr4::v8086_mode_extensions::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_protected_mode_virtual_interrupts()
{
    vmcs::host_cr4::protected_mode_virtual_interrupts::set(1UL);
    this->expect_true(vmcs::host_cr4::protected_mode_virtual_interrupts::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_time_stamp_disable()
{
    vmcs::host_cr4::time_stamp_disable::set(1UL);
    this->expect_true(vmcs::host_cr4::time_stamp_disable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_debugging_extensions()
{
    vmcs::host_cr4::debugging_extensions::set(1UL);
    this->expect_true(vmcs::host_cr4::debugging_extensions::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_page_size_extensions()
{
    vmcs::host_cr4::page_size_extensions::set(1UL);
    this->expect_true(vmcs::host_cr4::page_size_extensions::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_physical_address_extensions()
{
    vmcs::host_cr4::physical_address_extensions::set(1UL);
    this->expect_true(vmcs::host_cr4::physical_address_extensions::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_machine_check_enable()
{
    vmcs::host_cr4::machine_check_enable::set(1UL);
    this->expect_true(vmcs::host_cr4::machine_check_enable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_page_global_enable()
{
    vmcs::host_cr4::page_global_enable::set(1UL);
    this->expect_true(vmcs::host_cr4::page_global_enable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_performance_monitor_counter_enable()
{
    vmcs::host_cr4::performance_monitor_counter_enable::set(1UL);
    this->expect_true(vmcs::host_cr4::performance_monitor_counter_enable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_osfxsr()
{
    vmcs::host_cr4::osfxsr::set(1UL);
    this->expect_true(vmcs::host_cr4::osfxsr::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_osxmmexcpt()
{
    vmcs::host_cr4::osxmmexcpt::set(1UL);
    this->expect_true(vmcs::host_cr4::osxmmexcpt::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_vmx_enable_bit()
{
    vmcs::host_cr4::vmx_enable_bit::set(1UL);
    this->expect_true(vmcs::host_cr4::vmx_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_smx_enable_bit()
{
    vmcs::host_cr4::smx_enable_bit::set(1UL);
    this->expect_true(vmcs::host_cr4::smx_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_fsgsbase_enable_bit()
{
    vmcs::host_cr4::fsgsbase_enable_bit::set(1UL);
    this->expect_true(vmcs::host_cr4::fsgsbase_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_pcid_enable_bit()
{
    vmcs::host_cr4::pcid_enable_bit::set(1UL);
    this->expect_true(vmcs::host_cr4::pcid_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_osxsave()
{
    vmcs::host_cr4::osxsave::set(1UL);
    this->expect_true(vmcs::host_cr4::osxsave::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_smep_enable_bit()
{
    vmcs::host_cr4::smep_enable_bit::set(1UL);
    this->expect_true(vmcs::host_cr4::smep_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_smap_enable_bit()
{
    vmcs::host_cr4::smap_enable_bit::set(1UL);
    this->expect_true(vmcs::host_cr4::smap_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_cr4_protection_key_enable_bit()
{
    vmcs::host_cr4::protection_key_enable_bit::set(1UL);
    this->expect_true(vmcs::host_cr4::protection_key_enable_bit::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl()
{
    vmcs::guest_ia32_debugctl::set(100UL);
    this->expect_true(vmcs::guest_ia32_debugctl::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_lbr()
{
    vmcs::guest_ia32_debugctl::lbr::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::lbr::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_btf()
{
    vmcs::guest_ia32_debugctl::btf::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::btf::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_tr()
{
    vmcs::guest_ia32_debugctl::tr::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::tr::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_bts()
{
    vmcs::guest_ia32_debugctl::bts::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::bts::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_btint()
{
    vmcs::guest_ia32_debugctl::btint::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::btint::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_bt_off_os()
{
    vmcs::guest_ia32_debugctl::bt_off_os::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::bt_off_os::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_bt_off_user()
{
    vmcs::guest_ia32_debugctl::bt_off_user::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::bt_off_user::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_freeze_lbrs_on_pmi()
{
    vmcs::guest_ia32_debugctl::freeze_lbrs_on_pmi::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_lbrs_on_pmi::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_freeze_perfmon_on_pmi()
{
    vmcs::guest_ia32_debugctl::freeze_perfmon_on_pmi::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_perfmon_on_pmi::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_enable_uncore_pmi()
{
    vmcs::guest_ia32_debugctl::enable_uncore_pmi::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::enable_uncore_pmi::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_freeze_while_smm()
{
    vmcs::guest_ia32_debugctl::freeze_while_smm::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_while_smm::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_rtm_debug()
{
    vmcs::guest_ia32_debugctl::rtm_debug::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::rtm_debug::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_reserved()
{
    vmcs::guest_ia32_debugctl::reserved::set(0x10000UL);
    this->expect_true(vmcs::guest_ia32_debugctl::reserved::get() == 0x10000UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_efer()
{
    vmcs::guest_ia32_efer::set(100UL);
    this->expect_true(vmcs::guest_ia32_efer::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_efer_sce()
{
    vmcs::guest_ia32_efer::sce::set(1UL);
    this->expect_true(vmcs::guest_ia32_efer::sce::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_efer_lme()
{
    vmcs::guest_ia32_efer::lme::set(1UL);
    this->expect_true(vmcs::guest_ia32_efer::lme::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_efer_lma()
{
    vmcs::guest_ia32_efer::lma::set(1UL);
    this->expect_true(vmcs::guest_ia32_efer::lma::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_efer_nxe()
{
    vmcs::guest_ia32_efer::nxe::set(1UL);
    this->expect_true(vmcs::guest_ia32_efer::nxe::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_efer_reserved()
{
    vmcs::guest_ia32_efer::reserved::set(0x10000UL);
    this->expect_true(vmcs::guest_ia32_efer::reserved::get() == 0x10000UL);
}

void
vmcs_ut::test_vmcs_host_ia32_efer()
{
    vmcs::host_ia32_efer::set(100UL);
    this->expect_true(vmcs::host_ia32_efer::get() == 100UL);
}

void
vmcs_ut::test_vmcs_host_ia32_efer_sce()
{
    vmcs::host_ia32_efer::sce::set(1UL);
    this->expect_true(vmcs::host_ia32_efer::sce::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_ia32_efer_lme()
{
    vmcs::host_ia32_efer::lme::set(1UL);
    this->expect_true(vmcs::host_ia32_efer::lme::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_ia32_efer_lma()
{
    vmcs::host_ia32_efer::lma::set(1UL);
    this->expect_true(vmcs::host_ia32_efer::lma::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_ia32_efer_nxe()
{
    vmcs::host_ia32_efer::nxe::set(1UL);
    this->expect_true(vmcs::host_ia32_efer::nxe::get() == 1UL);
}

void
vmcs_ut::test_vmcs_host_ia32_efer_reserved()
{
    vmcs::host_ia32_efer::reserved::set(0x10000UL);
    this->expect_true(vmcs::host_ia32_efer::reserved::get() == 0x10000UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights()
{
    vmcs::guest_es_access_rights::set(100UL);
    this->expect_true(vmcs::guest_es_access_rights::exists());
    this->expect_true(vmcs::guest_es_access_rights::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_type()
{
    vmcs::guest_es_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::type::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_s()
{
    vmcs::guest_es_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::s::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_dpl()
{
    vmcs::guest_es_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::dpl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_present()
{
    vmcs::guest_es_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::present::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_avl()
{
    vmcs::guest_es_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::avl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_l()
{
    vmcs::guest_es_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::l::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_db()
{
    vmcs::guest_es_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::db::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_granularity()
{
    vmcs::guest_es_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::granularity::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_reserved()
{
    vmcs::guest_es_access_rights::reserved::set(0x10000U);
    this->expect_true(vmcs::guest_es_access_rights::reserved::get() == 0x10000U);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_unusable()
{
    vmcs::guest_es_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::unusable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights()
{
    vmcs::guest_cs_access_rights::set(100UL);
    this->expect_true(vmcs::guest_cs_access_rights::exists());
    this->expect_true(vmcs::guest_cs_access_rights::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_type()
{
    vmcs::guest_cs_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::type::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_s()
{
    vmcs::guest_cs_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::s::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_dpl()
{
    vmcs::guest_cs_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::dpl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_present()
{
    vmcs::guest_cs_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::present::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_avl()
{
    vmcs::guest_cs_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::avl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_l()
{
    vmcs::guest_cs_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::l::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_db()
{
    vmcs::guest_cs_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::db::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_granularity()
{
    vmcs::guest_cs_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::granularity::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_reserved()
{
    vmcs::guest_cs_access_rights::reserved::set(0x10000U);
    this->expect_true(vmcs::guest_cs_access_rights::reserved::get() == 0x10000U);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_unusable()
{
    vmcs::guest_cs_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::unusable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights()
{
    vmcs::guest_ss_access_rights::set(100UL);
    this->expect_true(vmcs::guest_ss_access_rights::exists());
    this->expect_true(vmcs::guest_ss_access_rights::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_type()
{
    vmcs::guest_ss_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::type::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_s()
{
    vmcs::guest_ss_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::s::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_dpl()
{
    vmcs::guest_ss_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::dpl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_present()
{
    vmcs::guest_ss_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::present::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_avl()
{
    vmcs::guest_ss_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::avl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_l()
{
    vmcs::guest_ss_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::l::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_db()
{
    vmcs::guest_ss_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::db::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_granularity()
{
    vmcs::guest_ss_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::granularity::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_reserved()
{
    vmcs::guest_ss_access_rights::reserved::set(0x10000U);
    this->expect_true(vmcs::guest_ss_access_rights::reserved::get() == 0x10000U);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_unusable()
{
    vmcs::guest_ss_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::unusable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights()
{
    vmcs::guest_ds_access_rights::set(100UL);
    this->expect_true(vmcs::guest_ds_access_rights::exists());
    this->expect_true(vmcs::guest_ds_access_rights::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_type()
{
    vmcs::guest_ds_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::type::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_s()
{
    vmcs::guest_ds_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::s::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_dpl()
{
    vmcs::guest_ds_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::dpl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_present()
{
    vmcs::guest_ds_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::present::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_avl()
{
    vmcs::guest_ds_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::avl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_l()
{
    vmcs::guest_ds_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::l::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_db()
{
    vmcs::guest_ds_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::db::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_granularity()
{
    vmcs::guest_ds_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::granularity::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_reserved()
{
    vmcs::guest_ds_access_rights::reserved::set(0x10000U);
    this->expect_true(vmcs::guest_ds_access_rights::reserved::get() == 0x10000U);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_unusable()
{
    vmcs::guest_ds_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::unusable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights()
{
    vmcs::guest_fs_access_rights::set(100UL);
    this->expect_true(vmcs::guest_fs_access_rights::exists());
    this->expect_true(vmcs::guest_fs_access_rights::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_type()
{
    vmcs::guest_fs_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::type::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_s()
{
    vmcs::guest_fs_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::s::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_dpl()
{
    vmcs::guest_fs_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::dpl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_present()
{
    vmcs::guest_fs_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::present::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_avl()
{
    vmcs::guest_fs_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::avl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_l()
{
    vmcs::guest_fs_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::l::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_db()
{
    vmcs::guest_fs_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::db::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_granularity()
{
    vmcs::guest_fs_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::granularity::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_reserved()
{
    vmcs::guest_fs_access_rights::reserved::set(0x10000U);
    this->expect_true(vmcs::guest_fs_access_rights::reserved::get() == 0x10000U);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_unusable()
{
    vmcs::guest_fs_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::unusable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights()
{
    vmcs::guest_gs_access_rights::set(100UL);
    this->expect_true(vmcs::guest_gs_access_rights::exists());
    this->expect_true(vmcs::guest_gs_access_rights::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_type()
{
    vmcs::guest_gs_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::type::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_s()
{
    vmcs::guest_gs_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::s::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_dpl()
{
    vmcs::guest_gs_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::dpl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_present()
{
    vmcs::guest_gs_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::present::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_avl()
{
    vmcs::guest_gs_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::avl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_l()
{
    vmcs::guest_gs_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::l::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_db()
{
    vmcs::guest_gs_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::db::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_granularity()
{
    vmcs::guest_gs_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::granularity::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_reserved()
{
    vmcs::guest_gs_access_rights::reserved::set(0x10000U);
    this->expect_true(vmcs::guest_gs_access_rights::reserved::get() == 0x10000U);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_unusable()
{
    vmcs::guest_gs_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::unusable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights()
{
    vmcs::guest_ldtr_access_rights::set(100UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::exists());
    this->expect_true(vmcs::guest_ldtr_access_rights::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_type()
{
    vmcs::guest_ldtr_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::type::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_s()
{
    vmcs::guest_ldtr_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::s::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_dpl()
{
    vmcs::guest_ldtr_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::dpl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_present()
{
    vmcs::guest_ldtr_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::present::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_avl()
{
    vmcs::guest_ldtr_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::avl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_l()
{
    vmcs::guest_ldtr_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::l::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_db()
{
    vmcs::guest_ldtr_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::db::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_granularity()
{
    vmcs::guest_ldtr_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::granularity::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_reserved()
{
    vmcs::guest_ldtr_access_rights::reserved::set(0x10000U);
    this->expect_true(vmcs::guest_ldtr_access_rights::reserved::get() == 0x10000U);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_unusable()
{
    vmcs::guest_ldtr_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::unusable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights()
{
    vmcs::guest_tr_access_rights::set(100UL);
    this->expect_true(vmcs::guest_tr_access_rights::exists());
    this->expect_true(vmcs::guest_tr_access_rights::get() == 100UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_type()
{
    vmcs::guest_tr_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::type::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_s()
{
    vmcs::guest_tr_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::s::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_dpl()
{
    vmcs::guest_tr_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::dpl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_present()
{
    vmcs::guest_tr_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::present::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_avl()
{
    vmcs::guest_tr_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::avl::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_l()
{
    vmcs::guest_tr_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::l::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_db()
{
    vmcs::guest_tr_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::db::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_granularity()
{
    vmcs::guest_tr_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::granularity::get() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_reserved()
{
    vmcs::guest_tr_access_rights::reserved::set(0x10000U);
    this->expect_true(vmcs::guest_tr_access_rights::reserved::get() == 0x10000U);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_unusable()
{
    vmcs::guest_tr_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::unusable::get() == 1UL);
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls()
{
    this->expect_true(vmcs::pin_based_vm_execution_controls::exists());

    vmcs::pin_based_vm_execution_controls::set(1UL);
    this->expect_true(vmcs::pin_based_vm_execution_controls::get() == 1UL);

    vmcs::pin_based_vm_execution_controls::set_if_exists(2UL);
    this->expect_true(vmcs::pin_based_vm_execution_controls::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls_external_interrupt_exiting()
{
    using namespace vmcs::pin_based_vm_execution_controls::external_interrupt_exiting;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls_nmi_exiting()
{
    using namespace vmcs::pin_based_vm_execution_controls::nmi_exiting;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls_virtual_nmis()
{
    using namespace vmcs::pin_based_vm_execution_controls::virtual_nmis;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls_activate_vmx_preemption_timer()
{
    using namespace vmcs::pin_based_vm_execution_controls::activate_vmx_preemption_timer;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls_process_posted_interrupts()
{
    using namespace vmcs::pin_based_vm_execution_controls::process_posted_interrupts;

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls()
{
    this->expect_true(vmcs::primary_processor_based_vm_execution_controls::exists());

    vmcs::primary_processor_based_vm_execution_controls::set(1UL);
    this->expect_true(vmcs::primary_processor_based_vm_execution_controls::get() == 1UL);

    vmcs::primary_processor_based_vm_execution_controls::set_if_exists(2UL);
    this->expect_true(vmcs::primary_processor_based_vm_execution_controls::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_interrupt_window_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::interrupt_window_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_use_tsc_offsetting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::use_tsc_offsetting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_hlt_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::hlt_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_invlpg_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::invlpg_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_mwait_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::mwait_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_rdpmc_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::rdpmc_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_rdtsc_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::rdtsc_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_cr3_load_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::cr3_load_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_cr3_store_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::cr3_store_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_cr8_load_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::cr8_load_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_cr8_store_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::cr8_store_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_use_tpr_shadow()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::use_tpr_shadow;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_nmi_window_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::nmi_window_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_mov_dr_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::mov_dr_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_unconditional_io_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::unconditional_io_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_use_io_bitmaps()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::use_io_bitmaps;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_monitor_trap_flag()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::monitor_trap_flag;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_use_msr_bitmaps()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::use_msr_bitmaps;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_monitor_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::monitor_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_pause_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::pause_exiting;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_activate_secondary_controls()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls;

    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exception_bitmap()
{
    this->expect_true(vmcs::exception_bitmap::exists());

    vmcs::exception_bitmap::set(1UL);
    this->expect_true(vmcs::exception_bitmap::get() == 1UL);

    vmcs::exception_bitmap::set_if_exists(2UL);
    this->expect_true(vmcs::exception_bitmap::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_page_fault_error_code_mask()
{
    this->expect_true(vmcs::page_fault_error_code_mask::exists());

    vmcs::page_fault_error_code_mask::set(1UL);
    this->expect_true(vmcs::page_fault_error_code_mask::get() == 1UL);

    vmcs::page_fault_error_code_mask::set_if_exists(2UL);
    this->expect_true(vmcs::page_fault_error_code_mask::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_page_fault_error_code_match()
{
    this->expect_true(vmcs::page_fault_error_code_match::exists());

    vmcs::page_fault_error_code_match::set(1UL);
    this->expect_true(vmcs::page_fault_error_code_match::get() == 1UL);

    vmcs::page_fault_error_code_match::set_if_exists(2UL);
    this->expect_true(vmcs::page_fault_error_code_match::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_cr3_target_count()
{
    this->expect_true(vmcs::cr3_target_count::exists());

    vmcs::cr3_target_count::set(1UL);
    this->expect_true(vmcs::cr3_target_count::get() == 1UL);

    vmcs::cr3_target_count::set_if_exists(2UL);
    this->expect_true(vmcs::cr3_target_count::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_vm_exit_controls()
{
    this->expect_true(vmcs::vm_exit_controls::exists());

    vmcs::vm_exit_controls::set(1UL);
    this->expect_true(vmcs::vm_exit_controls::get() == 1UL);

    vmcs::vm_exit_controls::set_if_exists(2UL);
    this->expect_true(vmcs::vm_exit_controls::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_vm_exit_controls_save_debug_controls()
{
    using namespace vmcs::vm_exit_controls::save_debug_controls;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_controls_host_address_space_size()
{
    using namespace vmcs::vm_exit_controls::host_address_space_size;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_controls_load_ia32_perf_global_ctrl()
{
    using namespace vmcs::vm_exit_controls::load_ia32_perf_global_ctrl;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_controls_acknowledge_interrupt_on_exit()
{
    using namespace vmcs::vm_exit_controls::acknowledge_interrupt_on_exit;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_controls_save_ia32_pat()
{
    using namespace vmcs::vm_exit_controls::save_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_controls_load_ia32_pat()
{
    using namespace vmcs::vm_exit_controls::load_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_controls_save_ia32_efer()
{
    using namespace vmcs::vm_exit_controls::save_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_controls_load_ia32_efer()
{
    using namespace vmcs::vm_exit_controls::load_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_controls_save_vmx_preemption_timer_value()
{
    using namespace vmcs::vm_exit_controls::save_vmx_preemption_timer_value;

    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_msr_store_count()
{
    this->expect_true(vmcs::vm_exit_msr_store_count::exists());

    vmcs::vm_exit_msr_store_count::set(1UL);
    this->expect_true(vmcs::vm_exit_msr_store_count::get() == 1UL);

    vmcs::vm_exit_msr_store_count::set_if_exists(2UL);
    this->expect_true(vmcs::vm_exit_msr_store_count::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_vm_exit_msr_load_count()
{
    this->expect_true(vmcs::vm_exit_msr_load_count::exists());

    vmcs::vm_exit_msr_load_count::set(1UL);
    this->expect_true(vmcs::vm_exit_msr_load_count::get() == 1UL);

    vmcs::vm_exit_msr_load_count::set_if_exists(2UL);
    this->expect_true(vmcs::vm_exit_msr_load_count::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_vm_entry_controls()
{
    this->expect_true(vmcs::vm_entry_controls::exists());

    vmcs::vm_entry_controls::set(1UL);
    this->expect_true(vmcs::vm_entry_controls::get() == 1UL);

    vmcs::vm_entry_controls::set_if_exists(2UL);
    this->expect_true(vmcs::vm_entry_controls::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_vm_entry_controls_load_debug_controls()
{
    using namespace vmcs::vm_entry_controls::load_debug_controls;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_entry_controls_ia_32e_mode_guest()
{
    using namespace vmcs::vm_entry_controls::ia_32e_mode_guest;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_entry_controls_entry_to_smm()
{
    using namespace vmcs::vm_entry_controls::entry_to_smm;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_entry_controls_deactivate_dual_monitor_treatment()
{
    using namespace vmcs::vm_entry_controls::deactivate_dual_monitor_treatment;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_entry_controls_load_ia32_perf_global_ctrl()
{
    using namespace vmcs::vm_entry_controls::load_ia32_perf_global_ctrl;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_entry_controls_load_ia32_pat()
{
    using namespace vmcs::vm_entry_controls::load_ia32_pat;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_entry_controls_load_ia32_efer()
{
    using namespace vmcs::vm_entry_controls::load_ia32_efer;

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_entry_msr_load_count()
{
    this->expect_true(vmcs::vm_entry_msr_load_count::exists());

    vmcs::vm_entry_msr_load_count::set(1UL);
    this->expect_true(vmcs::vm_entry_msr_load_count::get() == 1UL);

    vmcs::vm_entry_msr_load_count::set_if_exists(2UL);
    this->expect_true(vmcs::vm_entry_msr_load_count::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field()
{
    this->expect_true(vmcs::vm_entry_interruption_information_field::exists());

    vmcs::vm_entry_interruption_information_field::set(1UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::get() == 1UL);

    vmcs::vm_entry_interruption_information_field::set_if_exists(2UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field_vector()
{
    using namespace vmcs::vm_entry_interruption_information_field;

    set(0x101UL);
    this->expect_true(vector::get() == 0x1UL);
    this->expect_true(get() == 0x101UL);

    set_if_exists(0x222UL);
    this->expect_true(vector::get_if_exists() == 0x22UL);
    this->expect_true(get_if_exists() == 0x222UL);
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field_type()
{
    using namespace vmcs::vm_entry_interruption_information_field;

    set(0xf701UL);
    interruption_type::set(0x701UL);
    this->expect_true(interruption_type::get() == interruption_type::reserved);
    this->expect_true(get() == 0xf101UL);

    interruption_type::set_if_exists(0x303UL);
    this->expect_true(interruption_type::get_if_exists() == interruption_type::hardware_exception);
    this->expect_true(get() == 0xf301UL);
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field_deliver_error_code_bit()
{
    using namespace vmcs::vm_entry_interruption_information_field;

    set(0xffff0000UL);
    deliver_error_code_bit::enable();
    this->expect_true(deliver_error_code_bit::is_enabled());
    this->expect_true(get() == (0xffff0000UL | deliver_error_code_bit::mask));

    deliver_error_code_bit::disable();
    this->expect_true(deliver_error_code_bit::is_disabled());
    this->expect_true(get() == 0xffff0000UL);

    deliver_error_code_bit::enable_if_exists();
    this->expect_true(deliver_error_code_bit::is_enabled_if_exists());
    this->expect_true(get() == (0xffff0000UL | deliver_error_code_bit::mask));

    deliver_error_code_bit::disable_if_exists();
    this->expect_true(deliver_error_code_bit::is_disabled_if_exists());
    this->expect_true(get() == 0xffff0000UL);
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field_reserved()
{
    using namespace vmcs::vm_entry_interruption_information_field;

    set(0x701UL);
    reserved::set(0xbc02UL);
    this->expect_true(reserved::get() == 0xbc02UL);
    this->expect_true(get() == 0xbc02701UL);

    reserved::set_if_exists(0x1UL);
    this->expect_true(reserved::get_if_exists() == 0x1UL);
    this->expect_true(get() == 0x01701UL);
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field_valid_bit()
{
    using namespace vmcs::vm_entry_interruption_information_field;

    set(0x0fff0000UL);
    valid_bit::enable();
    this->expect_true(valid_bit::is_enabled());
    this->expect_true(get() == (0x0fff0000UL | valid_bit::mask));

    valid_bit::disable();
    this->expect_true(valid_bit::is_disabled());
    this->expect_true(get() == 0x0fff0000UL);

    valid_bit::enable_if_exists();
    this->expect_true(valid_bit::is_enabled_if_exists());
    this->expect_true(get() == (0x0fff0000UL | valid_bit::mask));

    valid_bit::disable_if_exists();
    this->expect_true(valid_bit::is_disabled_if_exists());
    this->expect_true(get() == 0x0fff0000UL);
}

void
vmcs_ut::test_vmcs_vm_entry_exception_error_code()
{
    this->expect_true(vmcs::vm_entry_exception_error_code::exists());

    vmcs::vm_entry_exception_error_code::set(1UL);
    this->expect_true(vmcs::vm_entry_exception_error_code::get() == 1UL);

    vmcs::vm_entry_exception_error_code::set_if_exists(2UL);
    this->expect_true(vmcs::vm_entry_exception_error_code::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_vm_entry_instruction_length()
{
    this->expect_true(vmcs::vm_entry_instruction_length::exists());

    vmcs::vm_entry_instruction_length::set(1UL);
    this->expect_true(vmcs::vm_entry_instruction_length::get() == 1UL);

    vmcs::vm_entry_instruction_length::set_if_exists(2UL);
    this->expect_true(vmcs::vm_entry_instruction_length::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_tpr_threshold()
{
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = ~(use_tpr_shadow::mask << 32);
    this->expect_false(vmcs::tpr_threshold::exists());

    g_msrs[addr] = use_tpr_shadow::mask << 32;
    this->expect_true(vmcs::tpr_threshold::exists());

    vmcs::tpr_threshold::set(0xF03UL);
    this->expect_true(vmcs::tpr_threshold::get() == 0xF03UL);

    vmcs::tpr_threshold::set_if_exists(0x333UL);
    this->expect_true(vmcs::tpr_threshold::get_if_exists() == 0x333UL);
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls()
{
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = ~(activate_secondary_controls::mask << 32);
    this->expect_false(vmcs::secondary_processor_based_vm_execution_controls::exists());

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    this->expect_true(vmcs::secondary_processor_based_vm_execution_controls::exists());

    vmcs::secondary_processor_based_vm_execution_controls::set(1UL);
    this->expect_true(vmcs::secondary_processor_based_vm_execution_controls::get() == 1UL);

    vmcs::secondary_processor_based_vm_execution_controls::set_if_exists(2UL);
    this->expect_true(vmcs::secondary_processor_based_vm_execution_controls::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_virtualize_apic_accesses()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::virtualize_apic_accesses;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_enable_ept()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_ept;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_descriptor_table_exiting()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::descriptor_table_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_enable_rdtscp()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_rdtscp;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_virtualize_x2apic_mode()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_enable_vpid()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_vpid;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_wbinvd_exiting()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::wbinvd_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_unrestricted_guest()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_apic_register_virtualization()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::apic_register_virtualization;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_virtual_interrupt_delivery()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_pause_loop_exiting()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::pause_loop_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_rdrand_exiting()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::rdrand_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_enable_invpcid()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_invpcid;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_enable_vm_functions()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_vm_functions;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_vmcs_shadowing()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::vmcs_shadowing;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_rdseed_exiting()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::rdseed_exiting;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_enable_pml()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_pml;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_ept_violation_ve()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::ept_violation_ve;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_secondary_processor_based_vm_execution_controls_enable_xsaves_xrstors()
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls::enable_xsaves_xrstors;
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;

    enable();
    this->expect_true(is_enabled());

    disable();
    this->expect_true(is_disabled());

    enable_if_allowed();
    this->expect_true(is_enabled_if_exists());

    disable_if_allowed();
    this->expect_true(is_disabled_if_exists());
}
