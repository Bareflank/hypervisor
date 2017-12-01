//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <bfgsl.h>

#include <intrinsics/x86/common_x64.h>
#include <intrinsics/x86/intel_x64.h>

#include <vmcs/vmcs_intel_x64.h>
#include <vmcs/vmcs_intel_x64_launch.h>
#include <vmcs/vmcs_intel_x64_resume.h>
#include <vmcs/vmcs_intel_x64_promote.h>

#include <test/vmcs_utils.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace x64;
using namespace intel_x64;

struct cpuid_regs g_cpuid_regs;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;
std::map<uint32_t, uint32_t> g_eax_cpuid;

bool g_virt_to_phys_return_nullptr = false;
bool g_phys_to_virt_return_nullptr = false;
bool g_vmclear_fails = false;
bool g_vmload_fails = false;
bool g_vmlaunch_fails = false;

size_t g_new_throws_bad_alloc;

uint64_t g_test_addr = 0U;
uint64_t g_virt_apic_addr = 0U;
uint8_t g_virt_apic_mem[0x81] = {0U};

uint64_t g_vmcs_link_addr = 1U;
uint32_t g_vmcs_link_mem[1] = {0U};

uint64_t g_pdpt_addr = 2U;
uint64_t g_pdpt_mem[4] = {0U};

std::map<uint64_t, void *> g_mock_mem {
    {
        {g_virt_apic_addr, static_cast<void *>(&g_virt_apic_mem)},
        {g_vmcs_link_addr, static_cast<void *>(&g_vmcs_link_mem)},
        {g_pdpt_addr, static_cast<void *>(&g_pdpt_mem)}
    }
};

static bool
test_vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs_fields[field];
    return true;
}

static bool
test_vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs_fields[field] = val;
    return true;
}

static uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

static bool
test_vmclear(void *ptr) noexcept
{ (void)ptr; return !g_vmclear_fails; }

static bool
test_vmptrld(void *ptr) noexcept
{ (void)ptr; return !g_vmload_fails; }

static bool
test_vmlaunch_demote() noexcept
{ return !g_vmlaunch_fails; }

static uint32_t
test_cpuid_eax(uint32_t val) noexcept
{ return g_eax_cpuid[val]; }

static void
vmcs_resume_fail(state_save_intel_x64 *state_save)
{
    (void) state_save;
}

static void
setup_launch_success_msrs()
{
    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = 0x7FFFFFFUL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;

    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0U;
    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xffffffffffffffffUL;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0U;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xffffffffffffffffUL;

    g_msrs[intel_x64::msrs::ia32_efer::addr] = intel_x64::msrs::ia32_efer::lma::mask;
}

static void
setup_vmcs_x64_state_srs(MockRepository &mocks, vmcs_intel_x64_state *state_in)
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

    mocks.OnCall(state_in, vmcs_intel_x64_state::es_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr_base).Return(0);
}

static void
setup_vmcs_x64_state_crs(MockRepository &mocks, vmcs_intel_x64_state *state_in)
{
    auto cr0 = 0UL;
    cr0 |= cr0::paging::mask;
    cr0 |= cr0::protection_enable::mask;

    auto cr4 = 0UL;
    cr4 |= cr4::physical_address_extensions::mask;

    auto rflags = 0UL;
    rflags |= rflags::interrupt_enable_flag::mask;

    mocks.OnCall(state_in, vmcs_intel_x64_state::cr0).Return(cr0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cr3).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cr4).Return(cr4);
    mocks.OnCall(state_in, vmcs_intel_x64_state::dr7).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::rflags).Return(rflags);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gdt_base).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::idt_base).Return(0);
}

static void
setup_vmcs_x64_state_msrs(MockRepository &mocks, vmcs_intel_x64_state *state_in)
{
    auto efer = 0UL;
    efer |= intel_x64::msrs::ia32_efer::lme::mask;
    efer |= intel_x64::msrs::ia32_efer::lma::mask;

    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_debugctl_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_pat_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_efer_msr).Return(efer);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_perf_global_ctrl_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_cs_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_esp_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_eip_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_fs_base_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_gs_base_msr).Return(0);
}

static void
setup_vmcs_x64_state_intrinsics(MockRepository &mocks, vmcs_intel_x64_state *state_in)
{
    setup_vmcs_x64_state_srs(mocks, state_in);
    setup_vmcs_x64_state_crs(mocks, state_in);
    setup_vmcs_x64_state_msrs(mocks, state_in);

    mocks.OnCall(state_in, vmcs_intel_x64_state::is_guest).Return(false);
    mocks.OnCall(state_in, vmcs_intel_x64_state::dump);
}

static void
setup_vmcs_intrinsics(MockRepository &mocks, memory_manager_x64 *mm)
{
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Do(test_virtptr_to_physint);
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_vmclear).Do(test_vmclear);
    mocks.OnCallFunc(_vmread).Do(test_vmread);
    mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
    mocks.OnCallFunc(_vmptrld).Do(test_vmptrld);
    mocks.OnCallFunc(_vmlaunch_demote).Do(test_vmlaunch_demote);
    mocks.OnCallFunc(_cpuid_eax).Do(test_cpuid_eax);
}

TEST_CASE("vmcs: launch_success")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);
    setup_vmcs_x64_state_intrinsics(mocks, host_state);
    setup_vmcs_x64_state_intrinsics(mocks, guest_state);
    setup_launch_success_msrs();

    vmcs_intel_x64 vmcs{};

    CHECK_NOTHROW(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_vmlaunch_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);
    setup_vmcs_x64_state_intrinsics(mocks, host_state);
    setup_vmcs_x64_state_intrinsics(mocks, guest_state);

    mocks.OnCall(guest_state, vmcs_intel_x64_state::is_guest).Return(true);
    mocks.OnCallFunc(_vmwrite).Return(true);
    Call &launch_call = mocks.ExpectCallFunc(vmcs_launch);
    mocks.OnCallFunc(_vmwrite).After(launch_call).Do(test_vmwrite);

    vmcs_intel_x64 vmcs{};
    std::vector<struct control_flow_path> cfg;

    setup_check_all_paths(cfg);

    for (const auto &sub_path : cfg) {
        sub_path.setup();
    }

    CHECK_THROWS(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_vmlaunch_demote_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);
    setup_vmcs_x64_state_intrinsics(mocks, host_state);
    setup_vmcs_x64_state_intrinsics(mocks, guest_state);

    mocks.OnCallFunc(_vmwrite).Return(true);
    Call &launch_call = mocks.ExpectCallFunc(_vmlaunch_demote).Return(false);
    mocks.OnCallFunc(_vmwrite).After(launch_call).Do(test_vmwrite);

    vmcs_intel_x64 vmcs{};
    std::vector<struct control_flow_path> cfg;

    setup_check_all_paths(cfg);

    for (const auto &sub_path : cfg) {
        sub_path.setup();
    }

    CHECK_THROWS(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_create_vmcs_region_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);
    setup_vmcs_x64_state_intrinsics(mocks, host_state);
    setup_vmcs_x64_state_intrinsics(mocks, guest_state);

    auto ___ = gsl::finally([&]
    { g_virt_to_phys_return_nullptr = false; });

    g_virt_to_phys_return_nullptr = true;

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_create_exit_handler_stack_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);

    vmcs_intel_x64 vmcs{};

    auto ___ = gsl::finally([&]
    { g_new_throws_bad_alloc = 0; });

    g_new_throws_bad_alloc = STACK_SIZE * 2;

    CHECK_THROWS(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_clear_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);

    vmcs_intel_x64 vmcs{};

    auto ___ = gsl::finally([&]
    { g_vmclear_fails = false; });

    g_vmclear_fails = true;
    CHECK_THROWS(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: launch_load_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);

    vmcs_intel_x64 vmcs{};

    auto ___ = gsl::finally([&]
    { g_vmload_fails = false; });

    g_vmload_fails = true;
    CHECK_THROWS(vmcs.launch(host_state, guest_state));
}

TEST_CASE("vmcs: promote_failure")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    setup_vmcs_intrinsics(mocks, mm);

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.promote(reinterpret_cast<char *>(0x1000UL)));
}

TEST_CASE("vmcs: resume_failure")
{
    MockRepository mocks;
    mocks.OnCallFunc(vmcs_resume).Do(vmcs_resume_fail);
    mocks.OnCallFunc(_vmread).Do(test_vmread);

    vmcs_intel_x64 vmcs{};
    CHECK_THROWS(vmcs.resume());
}

#endif
