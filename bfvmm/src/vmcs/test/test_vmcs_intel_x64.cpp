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

#include <intrinsics/rflags_x64.h>
#include <intrinsics/crs_intel_x64.h>
#include <intrinsics/vmx_intel_x64.h>

#define test_vm_control(ctl_under_test) \
    test_vm_control_with_args(ctl_under_test, gsl::cstring_span<>(__PRETTY_FUNCTION__), __LINE__)

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

enum vm_control_type
{
    pin_execution_ctl,
    primary_execution_ctl,
    secondary_execution_ctl,
    exit_ctl,
    entry_ctl
};

struct vm_control_api
{
    bool (*is_enabled)();
    void (*enable)();
    void (*disable)();
    void (*enable_if_allowed)(bool);
    void (*disable_if_allowed)(bool);
};

struct vm_control
{
    enum vm_control_type type;
    struct vm_control_api api;
    uint64_t mask;
    std::string name;
    unsigned int msr_addr;

    uint64_t (*get_ctls)();
    void (*set_ctls)(unsigned long);
};

enum vm_control_type g_ctl_type;
static struct vm_control_api g_ctl_api = { nullptr, nullptr, nullptr, nullptr, nullptr };
static struct vm_control g_ctl = { exit_ctl, g_ctl_api, 0UL, "", 0UL, nullptr, nullptr };
static struct control_flow_path path;

static void
init_vm_control_api(struct vm_control_api &api, bool (*is_enabled)(), void (*enable)(),
                    void (*disable)(), void (*enable_if_allowed)(bool), void (*disable_if_allowed)(bool))
{
    api.is_enabled = is_enabled;
    api.enable = enable;
    api.disable = disable;
    api.enable_if_allowed = enable_if_allowed;
    api.disable_if_allowed = disable_if_allowed;
}

static void
init_vm_control(struct vm_control &ctl, enum vm_control_type type,
                const struct vm_control_api &api, uint64_t mask, const std::string &name)
{
    ctl.type = type;
    ctl.api = api;
    ctl.mask = mask;
    ctl.name = name;

    if (type == pin_execution_ctl)
    {
        ctl.msr_addr = msrs::ia32_vmx_true_pinbased_ctls::addr;
        ctl.get_ctls = &vmcs::pin_based_vm_execution_controls::get;
        ctl.set_ctls = &vmcs::pin_based_vm_execution_controls::set;
    }

    if (type == primary_execution_ctl)
    {
        ctl.msr_addr = msrs::ia32_vmx_true_procbased_ctls::addr;
        ctl.get_ctls = &vmcs::primary_processor_based_vm_execution_controls::get;
        ctl.set_ctls = &vmcs::primary_processor_based_vm_execution_controls::set;
    }

    //case secondary_execution_ctl:
    //    ctl.msr_addr = msrs::ia32_vmx_procbased_ctls2::addr;
    //    ctl.get_ctls = &vmcs::secondary_processor_based_vm_execution_controls::get;
    //    ctl.set_ctls = &vmcs::secondary_processor_based_vm_execution_controls::set;
    //    break;

    if (type == exit_ctl)
    {
        ctl.msr_addr = msrs::ia32_vmx_true_exit_ctls::addr;
        ctl.get_ctls = &vmcs::vm_exit_controls::get;
        ctl.set_ctls = &vmcs::vm_exit_controls::set;
    }

    if (type == entry_ctl)
    {
        ctl.msr_addr = msrs::ia32_vmx_true_entry_ctls::addr;
        ctl.get_ctls = &vmcs::vm_entry_controls::get;
        ctl.set_ctls = &vmcs::vm_entry_controls::set;
    }
}

void
vmcs_ut::test_vm_control_with_args(const struct vm_control &ctl, gsl::cstring_span<> fut, int line)
{
    std::string allowed0_false = ctl.name + std::string(" is not allowed to be cleared to 0");
    std::string allowed1_false = ctl.name + std::string(" is not allowed to be set to 1");

    ctl.set_ctls(0UL);
    g_msrs[ctl.msr_addr] = ~ctl.mask;
    this->expect_no_exception_with_args([&] { ctl.api.disable(); }, fut, line);
    this->expect_true_with_args(ctl.get_ctls() == 0UL, ctl.name + std::string("- ctl.get_ctls == 0UL"), fut, line);
    this->expect_false_with_args(ctl.api.is_enabled(), ctl.name + std::string("::is_enabled()"), fut, line);

    g_msrs[ctl.msr_addr] = ctl.mask;
    this->expect_exception_with_args([&] { ctl.api.disable(); }, std::make_shared<std::logic_error>(allowed0_false), fut, line);

    g_msrs[ctl.msr_addr] = ctl.mask << 32;
    this->expect_no_exception_with_args([&] { ctl.api.enable(); }, fut, line);
    this->expect_true_with_args(ctl.get_ctls() == ctl.mask, ctl.name + std::string("- ctl.get_ctls() == ctl.mask"), fut, line);
    this->expect_true_with_args(ctl.api.is_enabled(), ctl.name + std::string("::is_enabled()"), fut, line);

    g_msrs[ctl.msr_addr] = ~(ctl.mask << 32);
    this->expect_exception_with_args([&] { ctl.api.enable(); }, std::make_shared<std::logic_error>(allowed1_false), fut, line);

    ctl.set_ctls(0UL);
    g_msrs[ctl.msr_addr] = ~ctl.mask;
    this->expect_no_exception_with_args([&] { ctl.api.disable_if_allowed(true); }, fut, line);
    this->expect_true_with_args(ctl.get_ctls() == 0UL, ctl.name + std::string("- ctl.get_ctls() == 0UL"), fut, line);

    g_msrs[ctl.msr_addr] = ctl.mask;
    this->expect_no_exception_with_args([&] { ctl.api.disable_if_allowed(true); }, fut, line);

    g_msrs[ctl.msr_addr] = ctl.mask << 32;
    this->expect_no_exception_with_args([&] { ctl.api.enable_if_allowed(true); }, fut, line);
    this->expect_true_with_args(ctl.get_ctls() == ctl.mask, ctl.name + std::string("- ctl.get_ctls() == ctl.mask"), fut, line);

    g_msrs[ctl.msr_addr] = ~(ctl.mask << 32);
    this->expect_no_exception_with_args([&] { ctl.api.enable_if_allowed(true); }, fut, line);
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
setup_vmcs_intrinsics(MockRepository &mocks, memory_manager *mm)
{
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);
    mocks.OnCall(mm, memory_manager::physint_to_virtptr).Do(physint_to_virtptr);
}

void
vmcs_ut::test_launch_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
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
    auto mm = mocks.Mock<memory_manager>();
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
    auto mm = mocks.Mock<memory_manager>();
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

        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), std::logic_error);
    });
}

void
vmcs_ut::test_launch_create_exit_handler_stack_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
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
    auto mm = mocks.Mock<memory_manager>();
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
    auto mm = mocks.Mock<memory_manager>();
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
vmcs_ut::test_vmcs_virtual_processor_identifier()
{
    vmcs::virtual_processor_identifier::set(100UL);
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::enable_vpid::mask;

    this->expect_true(vmcs::virtual_processor_identifier::get() == 100UL);
    this->expect_true(vmcs::virtual_processor_identifier::exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;

    this->expect_false(vmcs::virtual_processor_identifier::exists());
}

void
vmcs_ut::test_vmcs_posted_interrupt_notification_vector()
{
    vmcs::posted_interrupt_notification_vector::set(100UL);
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask;

    this->expect_true(vmcs::posted_interrupt_notification_vector::get() == 100UL);
    this->expect_true(vmcs::posted_interrupt_notification_vector::exists());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0x0;

    this->expect_false(vmcs::posted_interrupt_notification_vector::exists());
}

void
vmcs_ut::test_vmcs_eptp_index()
{
    vmcs::eptp_index::set(100UL);
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask;

    this->expect_true(vmcs::eptp_index::get() == 100UL);
    this->expect_true(vmcs::eptp_index::exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;

    this->expect_false(vmcs::eptp_index::exists());
}

void
vmcs_ut::test_vmcs_guest_es_selector()
{
    vmcs::guest_es_selector::set(100UL);

    this->expect_true(vmcs::guest_es_selector::get() == 100UL);
    this->expect_true(vmcs::guest_es_selector::exists());
}

void
vmcs_ut::test_vmcs_guest_es_selector_rpl()
{
    vmcs::guest_es_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_es_selector::rpl::get() == 1UL);

    vmcs::guest_es_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_es_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_selector_ti()
{
    vmcs::guest_es_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_es_selector::ti::get() == 1UL);

    vmcs::guest_es_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_es_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_selector_index()
{
    vmcs::guest_es_selector::index::set(1UL);
    this->expect_true(vmcs::guest_es_selector::index::get() == 1UL);

    vmcs::guest_es_selector::index::set(0UL);
    this->expect_true(vmcs::guest_es_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_selector()
{
    vmcs::guest_cs_selector::set(100UL);

    this->expect_true(vmcs::guest_cs_selector::get() == 100UL);
    this->expect_true(vmcs::guest_cs_selector::exists());
}

void
vmcs_ut::test_vmcs_guest_cs_selector_rpl()
{
    vmcs::guest_cs_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_cs_selector::rpl::get() == 1UL);

    vmcs::guest_cs_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_cs_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_selector_ti()
{
    vmcs::guest_cs_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_cs_selector::ti::get() == 1UL);

    vmcs::guest_cs_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_cs_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_selector_index()
{
    vmcs::guest_cs_selector::index::set(1UL);
    this->expect_true(vmcs::guest_cs_selector::index::get() == 1UL);

    vmcs::guest_cs_selector::index::set(0UL);
    this->expect_true(vmcs::guest_cs_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_selector()
{
    vmcs::guest_ss_selector::set(100UL);

    this->expect_true(vmcs::guest_ss_selector::get() == 100UL);
    this->expect_true(vmcs::guest_ss_selector::exists());
}

void
vmcs_ut::test_vmcs_guest_ss_selector_rpl()
{
    vmcs::guest_ss_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_ss_selector::rpl::get() == 1UL);

    vmcs::guest_ss_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_ss_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_selector_ti()
{
    vmcs::guest_ss_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_ss_selector::ti::get() == 1UL);

    vmcs::guest_ss_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_ss_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_selector_index()
{
    vmcs::guest_ss_selector::index::set(1UL);
    this->expect_true(vmcs::guest_ss_selector::index::get() == 1UL);

    vmcs::guest_ss_selector::index::set(0UL);
    this->expect_true(vmcs::guest_ss_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_selector()
{
    vmcs::guest_ds_selector::set(100UL);

    this->expect_true(vmcs::guest_ds_selector::get() == 100UL);
    this->expect_true(vmcs::guest_ds_selector::exists());
}

void
vmcs_ut::test_vmcs_guest_ds_selector_rpl()
{
    vmcs::guest_ds_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_ds_selector::rpl::get() == 1UL);

    vmcs::guest_ds_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_ds_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_selector_ti()
{
    vmcs::guest_ds_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_ds_selector::ti::get() == 1UL);

    vmcs::guest_ds_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_ds_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_selector_index()
{
    vmcs::guest_ds_selector::index::set(1UL);
    this->expect_true(vmcs::guest_ds_selector::index::get() == 1UL);

    vmcs::guest_ds_selector::index::set(0UL);
    this->expect_true(vmcs::guest_ds_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_selector()
{
    vmcs::guest_fs_selector::set(100UL);

    this->expect_true(vmcs::guest_fs_selector::get() == 100UL);
    this->expect_true(vmcs::guest_fs_selector::exists());
}

void
vmcs_ut::test_vmcs_guest_fs_selector_rpl()
{
    vmcs::guest_fs_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_fs_selector::rpl::get() == 1UL);

    vmcs::guest_fs_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_fs_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_selector_ti()
{
    vmcs::guest_fs_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_fs_selector::ti::get() == 1UL);

    vmcs::guest_fs_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_fs_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_selector_index()
{
    vmcs::guest_fs_selector::index::set(1UL);
    this->expect_true(vmcs::guest_fs_selector::index::get() == 1UL);

    vmcs::guest_fs_selector::index::set(0UL);
    this->expect_true(vmcs::guest_fs_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_selector()
{
    vmcs::guest_gs_selector::set(100UL);

    this->expect_true(vmcs::guest_gs_selector::get() == 100UL);
    this->expect_true(vmcs::guest_gs_selector::exists());
}

void
vmcs_ut::test_vmcs_guest_gs_selector_rpl()
{
    vmcs::guest_gs_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_gs_selector::rpl::get() == 1UL);

    vmcs::guest_gs_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_gs_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_selector_ti()
{
    vmcs::guest_gs_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_gs_selector::ti::get() == 1UL);

    vmcs::guest_gs_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_gs_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_selector_index()
{
    vmcs::guest_gs_selector::index::set(1UL);
    this->expect_true(vmcs::guest_gs_selector::index::get() == 1UL);

    vmcs::guest_gs_selector::index::set(0UL);
    this->expect_true(vmcs::guest_gs_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_selector()
{
    vmcs::guest_ldtr_selector::set(100UL);

    this->expect_true(vmcs::guest_ldtr_selector::get() == 100UL);
    this->expect_true(vmcs::guest_ldtr_selector::exists());
}

void
vmcs_ut::test_vmcs_guest_ldtr_selector_rpl()
{
    vmcs::guest_ldtr_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_ldtr_selector::rpl::get() == 1UL);

    vmcs::guest_ldtr_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_ldtr_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_selector_ti()
{
    vmcs::guest_ldtr_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_ldtr_selector::ti::get() == 1UL);

    vmcs::guest_ldtr_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_ldtr_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_selector_index()
{
    vmcs::guest_ldtr_selector::index::set(1UL);
    this->expect_true(vmcs::guest_ldtr_selector::index::get() == 1UL);

    vmcs::guest_ldtr_selector::index::set(0UL);
    this->expect_true(vmcs::guest_ldtr_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_selector()
{
    vmcs::guest_tr_selector::set(100UL);

    this->expect_true(vmcs::guest_tr_selector::get() == 100UL);
    this->expect_true(vmcs::guest_tr_selector::exists());
}

void
vmcs_ut::test_vmcs_guest_tr_selector_rpl()
{
    vmcs::guest_tr_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_tr_selector::rpl::get() == 1UL);

    vmcs::guest_tr_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_tr_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_selector_ti()
{
    vmcs::guest_tr_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_tr_selector::ti::get() == 1UL);

    vmcs::guest_tr_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_tr_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_selector_index()
{
    vmcs::guest_tr_selector::index::set(1UL);
    this->expect_true(vmcs::guest_tr_selector::index::get() == 1UL);

    vmcs::guest_tr_selector::index::set(0UL);
    this->expect_true(vmcs::guest_tr_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_interrupt_status()
{
    vmcs::guest_interrupt_status::set(100UL);
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask;

    this->expect_true(vmcs::guest_interrupt_status::get() == 100UL);
    this->expect_true(vmcs::guest_interrupt_status::exists());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;

    this->expect_false(vmcs::guest_interrupt_status::exists());
}

void
vmcs_ut::test_vmcs_host_es_selector()
{
    vmcs::host_es_selector::set(100UL);

    this->expect_true(vmcs::host_es_selector::get() == 100UL);
    this->expect_true(vmcs::host_es_selector::exists());
}

void
vmcs_ut::test_vmcs_host_es_selector_rpl()
{
    vmcs::guest_es_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_es_selector::rpl::get() == 1UL);

    vmcs::guest_es_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_es_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_es_selector_ti()
{
    vmcs::guest_es_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_es_selector::ti::get() == 1UL);

    vmcs::guest_es_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_es_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_es_selector_index()
{
    vmcs::guest_es_selector::index::set(1UL);
    this->expect_true(vmcs::guest_es_selector::index::get() == 1UL);

    vmcs::guest_es_selector::index::set(0UL);
    this->expect_true(vmcs::guest_es_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_cs_selector()
{
    vmcs::host_cs_selector::set(100UL);

    this->expect_true(vmcs::host_cs_selector::get() == 100UL);
    this->expect_true(vmcs::host_cs_selector::exists());
}

void
vmcs_ut::test_vmcs_host_cs_selector_rpl()
{
    vmcs::guest_cs_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_cs_selector::rpl::get() == 1UL);

    vmcs::guest_cs_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_cs_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_cs_selector_ti()
{
    vmcs::guest_cs_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_cs_selector::ti::get() == 1UL);

    vmcs::guest_cs_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_cs_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_cs_selector_index()
{
    vmcs::guest_cs_selector::index::set(1UL);
    this->expect_true(vmcs::guest_cs_selector::index::get() == 1UL);

    vmcs::guest_cs_selector::index::set(0UL);
    this->expect_true(vmcs::guest_cs_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ss_selector()
{
    vmcs::host_ss_selector::set(100UL);

    this->expect_true(vmcs::host_ss_selector::get() == 100UL);
    this->expect_true(vmcs::host_ss_selector::exists());
}

void
vmcs_ut::test_vmcs_host_ss_selector_rpl()
{
    vmcs::guest_ss_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_ss_selector::rpl::get() == 1UL);

    vmcs::guest_ss_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_ss_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ss_selector_ti()
{
    vmcs::guest_ss_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_ss_selector::ti::get() == 1UL);

    vmcs::guest_ss_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_ss_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ss_selector_index()
{
    vmcs::guest_ss_selector::index::set(1UL);
    this->expect_true(vmcs::guest_ss_selector::index::get() == 1UL);

    vmcs::guest_ss_selector::index::set(0UL);
    this->expect_true(vmcs::guest_ss_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ds_selector()
{
    vmcs::host_ds_selector::set(100UL);

    this->expect_true(vmcs::host_ds_selector::get() == 100UL);
    this->expect_true(vmcs::host_ds_selector::exists());
}

void
vmcs_ut::test_vmcs_host_ds_selector_rpl()
{
    vmcs::guest_ds_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_ds_selector::rpl::get() == 1UL);

    vmcs::guest_ds_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_ds_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ds_selector_ti()
{
    vmcs::guest_ds_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_ds_selector::ti::get() == 1UL);

    vmcs::guest_ds_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_ds_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ds_selector_index()
{
    vmcs::guest_ds_selector::index::set(1UL);
    this->expect_true(vmcs::guest_ds_selector::index::get() == 1UL);

    vmcs::guest_ds_selector::index::set(0UL);
    this->expect_true(vmcs::guest_ds_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_fs_selector()
{
    vmcs::host_fs_selector::set(100UL);

    this->expect_true(vmcs::host_fs_selector::get() == 100UL);
    this->expect_true(vmcs::host_fs_selector::exists());
}

void
vmcs_ut::test_vmcs_host_fs_selector_rpl()
{
    vmcs::guest_fs_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_fs_selector::rpl::get() == 1UL);

    vmcs::guest_fs_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_fs_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_fs_selector_ti()
{
    vmcs::guest_fs_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_fs_selector::ti::get() == 1UL);

    vmcs::guest_fs_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_fs_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_fs_selector_index()
{
    vmcs::guest_fs_selector::index::set(1UL);
    this->expect_true(vmcs::guest_fs_selector::index::get() == 1UL);

    vmcs::guest_fs_selector::index::set(0UL);
    this->expect_true(vmcs::guest_fs_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_gs_selector()
{
    vmcs::host_gs_selector::set(100UL);

    this->expect_true(vmcs::host_gs_selector::get() == 100UL);
    this->expect_true(vmcs::host_gs_selector::exists());
}

void
vmcs_ut::test_vmcs_host_gs_selector_rpl()
{
    vmcs::guest_gs_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_gs_selector::rpl::get() == 1UL);

    vmcs::guest_gs_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_gs_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_gs_selector_ti()
{
    vmcs::guest_gs_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_gs_selector::ti::get() == 1UL);

    vmcs::guest_gs_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_gs_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_gs_selector_index()
{
    vmcs::guest_gs_selector::index::set(1UL);
    this->expect_true(vmcs::guest_gs_selector::index::get() == 1UL);

    vmcs::guest_gs_selector::index::set(0UL);
    this->expect_true(vmcs::guest_gs_selector::index::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_tr_selector()
{
    vmcs::host_tr_selector::set(100UL);

    this->expect_true(vmcs::host_tr_selector::get() == 100UL);
    this->expect_true(vmcs::host_tr_selector::exists());
}

void
vmcs_ut::test_vmcs_host_tr_selector_rpl()
{
    vmcs::guest_tr_selector::rpl::set(1UL);
    this->expect_true(vmcs::guest_tr_selector::rpl::get() == 1UL);

    vmcs::guest_tr_selector::rpl::set(0UL);
    this->expect_true(vmcs::guest_tr_selector::rpl::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_tr_selector_ti()
{
    vmcs::guest_tr_selector::ti::set(1UL);
    this->expect_true(vmcs::guest_tr_selector::ti::get() == 1UL);

    vmcs::guest_tr_selector::ti::set(0UL);
    this->expect_true(vmcs::guest_tr_selector::ti::get() == 0UL);
}

void
vmcs_ut::test_vmcs_host_tr_selector_index()
{
    vmcs::guest_tr_selector::index::set(1UL);
    this->expect_true(vmcs::guest_tr_selector::index::get() == 1UL);

    vmcs::guest_tr_selector::index::set(0UL);
    this->expect_true(vmcs::guest_tr_selector::index::get() == 0UL);
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
    vmcs::guest_cr0::set(100UL);
    this->expect_true(vmcs::guest_cr0::get() == 100UL);
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
    vmcs::guest_cr4::set(100UL);
    this->expect_true(vmcs::guest_cr4::get() == 100UL);
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
    vmcs::host_cr0::set(100UL);
    this->expect_true(vmcs::host_cr0::get() == 100UL);
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
    vmcs::host_cr4::set(100UL);
    this->expect_true(vmcs::host_cr4::get() == 100UL);
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
    vmcs::pin_based_vm_execution_controls::set(1UL);
    this->expect_true(vmcs::pin_based_vm_execution_controls::get() == 1UL);
    this->expect_true(vmcs::pin_based_vm_execution_controls::exists());
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls_external_interrupt_exiting()
{
    using namespace vmcs::pin_based_vm_execution_controls::external_interrupt_exiting;

    g_ctl_type = pin_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls_nmi_exiting()
{
    using namespace vmcs::pin_based_vm_execution_controls::nmi_exiting;

    g_ctl_type = pin_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls_virtual_nmis()
{
    using namespace vmcs::pin_based_vm_execution_controls::virtual_nmis;

    g_ctl_type = pin_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls_activate_vmx_preemption_timer()
{
    using namespace vmcs::pin_based_vm_execution_controls::activate_vmx_preemption_timer;

    g_ctl_type = pin_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_pin_based_vm_execution_controls_process_posted_interrupts()
{
    using namespace vmcs::pin_based_vm_execution_controls::process_posted_interrupts;

    g_ctl_type = pin_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls()
{
    vmcs::primary_processor_based_vm_execution_controls::set(1UL);
    this->expect_true(vmcs::primary_processor_based_vm_execution_controls::get() == 1UL);
    this->expect_true(vmcs::primary_processor_based_vm_execution_controls::exists());
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_interrupt_window_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::interrupt_window_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_use_tsc_offsetting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::use_tsc_offsetting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_hlt_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::hlt_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_invlpg_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::invlpg_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_mwait_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::mwait_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_rdpmc_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::rdpmc_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_rdtsc_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::rdtsc_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_cr3_load_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::cr3_load_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_cr3_store_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::cr3_store_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_cr8_load_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::cr8_load_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_cr8_store_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::cr8_store_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_use_tpr_shadow()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::use_tpr_shadow;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_nmi_window_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::nmi_window_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_mov_dr_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::mov_dr_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_unconditional_io_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::unconditional_io_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_use_io_bitmaps()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::use_io_bitmaps;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_monitor_trap_flag()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::monitor_trap_flag;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_use_msr_bitmaps()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::use_msr_bitmaps;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_monitor_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::monitor_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_pause_exiting()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::pause_exiting;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_primary_processor_based_vm_execution_controls_activate_secondary_controls()
{
    using namespace vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls;

    g_ctl_type = primary_execution_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_exception_bitmap()
{
    vmcs::exception_bitmap::set(1UL);
    this->expect_true(vmcs::exception_bitmap::get() == 1UL);
    this->expect_true(vmcs::exception_bitmap::exists());
}

void
vmcs_ut::test_vmcs_page_fault_error_code_mask()
{
    vmcs::page_fault_error_code_mask::set(1UL);
    this->expect_true(vmcs::page_fault_error_code_mask::get() == 1UL);
    this->expect_true(vmcs::page_fault_error_code_mask::exists());
}

void
vmcs_ut::test_vmcs_page_fault_error_code_match()
{
    vmcs::page_fault_error_code_match::set(1UL);
    this->expect_true(vmcs::page_fault_error_code_match::get() == 1UL);
    this->expect_true(vmcs::page_fault_error_code_match::exists());
}

void
vmcs_ut::test_vmcs_cr3_target_count()
{
    vmcs::cr3_target_count::set(1UL);
    this->expect_true(vmcs::cr3_target_count::get() == 1UL);
    this->expect_true(vmcs::cr3_target_count::exists());
}

void
vmcs_ut::test_vmcs_vm_exit_controls()
{
    vmcs::vm_exit_controls::set(1UL);
    this->expect_true(vmcs::vm_exit_controls::get() == 1UL);
    this->expect_true(vmcs::vm_exit_controls::exists());
}

void
vmcs_ut::test_vmcs_vm_exit_controls_save_debug_controls()
{
    using namespace vmcs::vm_exit_controls::save_debug_controls;

    g_ctl_type = exit_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_exit_controls_host_address_space_size()
{
    using namespace vmcs::vm_exit_controls::host_address_space_size;

    g_ctl_type = exit_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_exit_controls_load_ia32_perf_global_ctrl()
{
    using namespace vmcs::vm_exit_controls::load_ia32_perf_global_ctrl;

    g_ctl_type = exit_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_exit_controls_acknowledge_interrupt_on_exit()
{
    using namespace vmcs::vm_exit_controls::acknowledge_interrupt_on_exit;

    g_ctl_type = exit_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_exit_controls_save_ia32_pat()
{
    using namespace vmcs::vm_exit_controls::save_ia32_pat;

    g_ctl_type = exit_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_exit_controls_load_ia32_pat()
{
    using namespace vmcs::vm_exit_controls::load_ia32_pat;

    g_ctl_type = exit_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_exit_controls_save_ia32_efer()
{
    using namespace vmcs::vm_exit_controls::save_ia32_efer;

    g_ctl_type = exit_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_exit_controls_load_ia32_efer()
{
    using namespace vmcs::vm_exit_controls::load_ia32_efer;

    g_ctl_type = exit_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_exit_controls_save_vmx_preemption_timer_value()
{
    using namespace vmcs::vm_exit_controls::save_vmx_preemption_timer_value;

    g_ctl_type = exit_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_exit_msr_store_count()
{
    vmcs::vm_exit_msr_store_count::set(1UL);
    this->expect_true(vmcs::vm_exit_msr_store_count::get() == 1UL);
    this->expect_true(vmcs::vm_exit_msr_store_count::exists());
}

void
vmcs_ut::test_vmcs_vm_exit_msr_load_count()
{
    vmcs::vm_exit_msr_load_count::set(1UL);
    this->expect_true(vmcs::vm_exit_msr_load_count::get() == 1UL);
    this->expect_true(vmcs::vm_exit_msr_load_count::exists());
}

void
vmcs_ut::test_vmcs_vm_entry_controls()
{
    vmcs::vm_entry_controls::set(1UL);
    this->expect_true(vmcs::vm_entry_controls::get() == 1UL);
    this->expect_true(vmcs::vm_entry_controls::exists());
}

void
vmcs_ut::test_vmcs_vm_entry_controls_load_debug_controls()
{
    using namespace vmcs::vm_entry_controls::load_debug_controls;

    g_ctl_type = entry_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_entry_controls_ia_32e_mode_guest()
{
    using namespace vmcs::vm_entry_controls::ia_32e_mode_guest;

    g_ctl_type = entry_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_entry_controls_entry_to_smm()
{
    using namespace vmcs::vm_entry_controls::entry_to_smm;

    g_ctl_type = entry_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_entry_controls_deactivate_dual_monitor_treatment()
{
    using namespace vmcs::vm_entry_controls::deactivate_dual_monitor_treatment;

    g_ctl_type = entry_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_entry_controls_load_ia32_perf_global_ctrl()
{
    using namespace vmcs::vm_entry_controls::load_ia32_perf_global_ctrl;

    g_ctl_type = entry_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_entry_controls_load_ia32_pat()
{
    using namespace vmcs::vm_entry_controls::load_ia32_pat;

    g_ctl_type = entry_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_entry_controls_load_ia32_efer()
{
    using namespace vmcs::vm_entry_controls::load_ia32_efer;

    g_ctl_type = entry_ctl;
    init_vm_control_api(g_ctl_api, &is_enabled, &enable, &disable, &enable_if_allowed, &disable_if_allowed);
    init_vm_control(g_ctl, g_ctl_type, g_ctl_api, mask, std::string(name));

    this->test_vm_control(g_ctl);
}

void
vmcs_ut::test_vmcs_vm_entry_msr_load_count()
{
    vmcs::vm_entry_msr_load_count::set(1UL);
    this->expect_true(vmcs::vm_entry_msr_load_count::get() == 1UL);
    this->expect_true(vmcs::vm_entry_msr_load_count::exists());
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field()
{
    vmcs::vm_entry_interruption_information_field::set(1UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::get() == 1UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::exists());
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field_vector()
{
    vmcs::vm_entry_interruption_information_field::vector::set(0x101UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::get() == 0x1UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::vector::get() == 0x1UL);
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field_type()
{
    vmcs::vm_entry_interruption_information_field::set(0x701UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::type::get() == vmcs::vm_entry_interruption_information_field::type::other_event);

    vmcs::vm_entry_interruption_information_field::type::set(0x301UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::type::get() == vmcs::vm_entry_interruption_information_field::type::reserved);
    this->expect_true(vmcs::vm_entry_interruption_information_field::get() == 0x101UL);
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field_deliver_error_code_bit()
{
    vmcs::vm_entry_interruption_information_field::set(0x701UL);
    this->expect_false(vmcs::vm_entry_interruption_information_field::deliver_error_code_bit::is_set());

    vmcs::vm_entry_interruption_information_field::deliver_error_code_bit::set();
    this->expect_true(vmcs::vm_entry_interruption_information_field::deliver_error_code_bit::is_set());
    this->expect_true(vmcs::vm_entry_interruption_information_field::get() == (0x701UL | vmcs::vm_entry_interruption_information_field::deliver_error_code_bit::mask));

    vmcs::vm_entry_interruption_information_field::deliver_error_code_bit::clear();
    this->expect_false(vmcs::vm_entry_interruption_information_field::deliver_error_code_bit::is_set());
    this->expect_true(vmcs::vm_entry_interruption_information_field::get() == 0x701UL);
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field_reserved()
{
    vmcs::vm_entry_interruption_information_field::set(0x701UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::reserved::get() == 0UL);

    vmcs::vm_entry_interruption_information_field::reserved::set(0x1UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::reserved::get() == 0x1UL);
    this->expect_true(vmcs::vm_entry_interruption_information_field::get() == 0x1701UL);
}

void
vmcs_ut::test_vmcs_vm_entry_interruption_information_field_valid_bit()
{
    vmcs::vm_entry_interruption_information_field::set(0x701UL);
    this->expect_false(vmcs::vm_entry_interruption_information_field::valid_bit::is_set());

    vmcs::vm_entry_interruption_information_field::valid_bit::set();
    this->expect_true(vmcs::vm_entry_interruption_information_field::valid_bit::is_set());
    this->expect_true(vmcs::vm_entry_interruption_information_field::get() == (0x701UL | vmcs::vm_entry_interruption_information_field::valid_bit::mask));

    vmcs::vm_entry_interruption_information_field::valid_bit::clear();
    this->expect_false(vmcs::vm_entry_interruption_information_field::valid_bit::is_set());
    this->expect_true(vmcs::vm_entry_interruption_information_field::get() == 0x701UL);
}

void
vmcs_ut::test_vmcs_vm_entry_exception_error_code()
{
    vmcs::vm_entry_exception_error_code::set(1UL);
    this->expect_true(vmcs::vm_entry_exception_error_code::get() == 1UL);
    this->expect_true(vmcs::vm_entry_exception_error_code::exists());
}

void
vmcs_ut::test_vmcs_vm_entry_instruction_length()
{
    vmcs::vm_entry_instruction_length::set(1UL);
    this->expect_true(vmcs::vm_entry_instruction_length::get() == 1UL);
    this->expect_true(vmcs::vm_entry_instruction_length::exists());
}
