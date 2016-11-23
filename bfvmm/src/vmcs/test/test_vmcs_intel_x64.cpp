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

#include <vmcs/vmcs_intel_x64_helpers.h>
#include <vmcs/vmcs_intel_x64_resume.h>
#include <vmcs/vmcs_intel_x64_promote.h>
#include <vmcs/vmcs_intel_x64_16bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_16bit_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_16bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_host_state_field.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_control_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_read_only_data_field.h>
#include <vmcs/vmcs_intel_x64_64bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_host_state_fields.h>

#include <intrinsics/tss_x64.h>
#include <intrinsics/rflags_x64.h>
#include <intrinsics/crs_intel_x64.h>
#include <intrinsics/vmx_intel_x64.h>
#include <intrinsics/msrs_intel_x64.h>

using namespace x64;
using namespace intel_x64;
using namespace msrs;
using namespace vmcs;

extern bool g_vmread_fails;
extern bool g_vmwrite_fails;
extern bool g_vmclear_fails;
extern bool g_vmload_fails;
extern size_t g_new_throws_bad_alloc;

extern void setup_check_control_vmx_controls_all_paths(std::vector<struct control_flow_path> &cfg);
extern void setup_check_host_state_all_paths(std::vector<struct control_flow_path> &cfg);
extern void setup_check_guest_state_all_paths(std::vector<struct control_flow_path> &cfg);

static struct control_flow_path path;

static std::map<uint64_t, const char *> vm_instruction_error_codes
{
    {
        {1U, "VMCALL executed in VMX root operation"},
        {2U, "VMCLEAR with invalid physical address"},
        {3U, "VMCLEAR with VMXON pointer"},
        {4U, "VMLAUNCH with non-clear VMCS"},
        {5U, "VMRESUME with non-launched VMCS"},
        {6U, "VMRESUME after VMXOFF (VMXOFF AND VMXON between VMLAUNCH and VMRESUME)"},
        {7U, "VM entry with invalid control field(s)"},
        {8U, "VM entry with invalid host-state field(s)"},
        {9U, "VMPTRLD with invalid physical address"},
        {10U, "VMPTRLD with VMXON pointer"},
        {11U, "VMPTRLD with incorrect VMCS revision identifier"},
        {12U, "VMREAD/VMWRITE from/to unsupported VMCS component"},
        {13U, "VMWRITE to read-only VMCS component"},
        {15U, "VMXON executed in VMX root operation"},
        {16U, "VM entry with invalid executive-VMCS pointer"},
        {17U, "VM entry with non-launched executive VMCS"},
        {
            18U, "VM entry with executive-VMCS pointer not VMXON pointer "
            "(when attempting to deactivate the dual-monitor treatment of SMIs and SMM)"
        },
        {
            19U, "VMCALL with non-clear VMCS (when attempting to activate"
            " the dual-monitor treatment of SMIs and SMM)"
        },
        {20U, "VMCALL with invalid VM-exit control fields"},
        {
            22U, "VMCALL with incorrect MSEG revision identifier (when attempting "
            "to activate the dual-monitor treatment of SMIs and SMM)"
        },
        {23U, "VMXOFF under dual-monitor treatment of SMIs and SMM"},
        {
            24U, "VMCALL with invalid SMM-monitor features (when attempting to "
            "activate the dual-monitor treatment of SMIs and SMM)"
        },
        {
            25U, "VM entry with invalid VM-execution control fields in executive"
            " VMCS (when attempting to return from SMM)"
        },
        {26U, "VM entry with events blocked by MOV SS"},
        {28U, "Invalid operand to INVEPT/INVVPID"},
        {29U, "Unknown VM-instruction error"}
    }
};

static std::map<uint64_t, std::string> exit_reasons
{
    {
        {vmcs::exit_reason::basic_exit_reason::exception_or_non_maskable_interrupt, "exception_or_non_maskable_interrupt"_s},
        {vmcs::exit_reason::basic_exit_reason::external_interrupt, "external_interrupt"_s},
        {vmcs::exit_reason::basic_exit_reason::triple_fault, "triple_fault"_s},
        {vmcs::exit_reason::basic_exit_reason::init_signal, "init_signal"_s},
        {vmcs::exit_reason::basic_exit_reason::sipi, "sipi"_s},
        {vmcs::exit_reason::basic_exit_reason::smi, "smi"_s},
        {vmcs::exit_reason::basic_exit_reason::other_smi, "other_smi"_s},
        {vmcs::exit_reason::basic_exit_reason::interrupt_window, "interrupt_window"_s},
        {vmcs::exit_reason::basic_exit_reason::nmi_window, "nmi_window"_s},
        {vmcs::exit_reason::basic_exit_reason::task_switch, "task_switch"_s},
        {vmcs::exit_reason::basic_exit_reason::cpuid, "cpuid"_s},
        {vmcs::exit_reason::basic_exit_reason::getsec, "getsec"_s},
        {vmcs::exit_reason::basic_exit_reason::hlt, "hlt"_s},
        {vmcs::exit_reason::basic_exit_reason::invd, "invd"_s},
        {vmcs::exit_reason::basic_exit_reason::invlpg, "invlpg"_s},
        {vmcs::exit_reason::basic_exit_reason::rdpmc, "rdpmc"_s},
        {vmcs::exit_reason::basic_exit_reason::rdtsc, "rdtsc"_s},
        {vmcs::exit_reason::basic_exit_reason::rsm, "rsm"_s},
        {vmcs::exit_reason::basic_exit_reason::vmcall, "vmcall"_s},
        {vmcs::exit_reason::basic_exit_reason::vmclear, "vmclear"_s},
        {vmcs::exit_reason::basic_exit_reason::vmlaunch, "vmlaunch"_s},
        {vmcs::exit_reason::basic_exit_reason::vmptrld, "vmptrld"_s},
        {vmcs::exit_reason::basic_exit_reason::vmptrst, "vmptrst"_s},
        {vmcs::exit_reason::basic_exit_reason::vmread, "vmread"_s},
        {vmcs::exit_reason::basic_exit_reason::vmresume, "vmresume"_s},
        {vmcs::exit_reason::basic_exit_reason::vmwrite, "vmwrite"_s},
        {vmcs::exit_reason::basic_exit_reason::vmxoff, "vmxoff"_s},
        {vmcs::exit_reason::basic_exit_reason::vmxon, "vmxon"_s},
        {vmcs::exit_reason::basic_exit_reason::control_register_accesses, "control_register_accesses"_s},
        {vmcs::exit_reason::basic_exit_reason::mov_dr, "mov_dr"_s},
        {vmcs::exit_reason::basic_exit_reason::io_instruction, "io_instruction"_s},
        {vmcs::exit_reason::basic_exit_reason::rdmsr, "rdmsr"_s},
        {vmcs::exit_reason::basic_exit_reason::wrmsr, "wrmsr"_s},
        {vmcs::exit_reason::basic_exit_reason::vm_entry_failure_invalid_guest_state, "vm_entry_failure_invalid_guest_state"_s},
        {vmcs::exit_reason::basic_exit_reason::vm_entry_failure_msr_loading, "vm_entry_failure_msr_loading"_s},
        {vmcs::exit_reason::basic_exit_reason::mwait, "mwait"_s},
        {vmcs::exit_reason::basic_exit_reason::monitor_trap_flag, "monitor_trap_flag"_s},
        {vmcs::exit_reason::basic_exit_reason::monitor, "monitor"_s},
        {vmcs::exit_reason::basic_exit_reason::pause, "pause"_s},
        {vmcs::exit_reason::basic_exit_reason::vm_entry_failure_machine_check_event, "vm_entry_failure_machine_check_event"_s},
        {vmcs::exit_reason::basic_exit_reason::tpr_below_threshold, "tpr_below_threshold"_s},
        {vmcs::exit_reason::basic_exit_reason::apic_access, "apic_access"_s},
        {vmcs::exit_reason::basic_exit_reason::virtualized_eoi, "virtualized_eoi"_s},
        {vmcs::exit_reason::basic_exit_reason::access_to_gdtr_or_idtr, "access_to_gdtr_or_idtr"_s},
        {vmcs::exit_reason::basic_exit_reason::access_to_ldtr_or_tr, "access_to_ldtr_or_tr"_s},
        {vmcs::exit_reason::basic_exit_reason::ept_violation, "ept_violation"_s},
        {vmcs::exit_reason::basic_exit_reason::ept_misconfiguration, "ept_misconfiguration"_s},
        {vmcs::exit_reason::basic_exit_reason::invept, "invept"_s},
        {vmcs::exit_reason::basic_exit_reason::rdtscp, "rdtscp"_s},
        {vmcs::exit_reason::basic_exit_reason::vmx_preemption_timer_expired, "vmx_preemption_timer_expired"_s},
        {vmcs::exit_reason::basic_exit_reason::invvpid, "invvpid"_s},
        {vmcs::exit_reason::basic_exit_reason::wbinvd, "wbinvd"_s},
        {vmcs::exit_reason::basic_exit_reason::xsetbv, "xsetbv"_s},
        {vmcs::exit_reason::basic_exit_reason::apic_write, "apic_write"_s},
        {vmcs::exit_reason::basic_exit_reason::rdrand, "rdrand"_s},
        {vmcs::exit_reason::basic_exit_reason::invpcid, "invpcid"_s},
        {vmcs::exit_reason::basic_exit_reason::vmfunc, "vmfunc"_s},
        {vmcs::exit_reason::basic_exit_reason::rdseed, "rdseed"_s},
        {vmcs::exit_reason::basic_exit_reason::xsaves, "xsaves"_s},
        {vmcs::exit_reason::basic_exit_reason::xrstors, "xrstors"_s},
        {0x0000BEEF, "unknown"_s}
    }
};

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
setup_check_all_paths(std::vector<struct control_flow_path> &cfg)
{
    std::vector<struct control_flow_path> sub_cfg;

    setup_check_control_vmx_controls_all_paths(sub_cfg);
    setup_check_host_state_all_paths(sub_cfg);
    setup_check_guest_state_all_paths(sub_cfg);

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
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);
    setup_vmcs_x64_state_intrinsics(mocks, host_state);
    setup_vmcs_x64_state_intrinsics(mocks, guest_state);
    setup_launch_success_msrs();

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        this->expect_no_exception([&] { vmcs.launch(host_state, guest_state); });
    });
}

void
vmcs_ut::test_launch_vmlaunch_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);
    setup_vmcs_x64_state_intrinsics(mocks, host_state);
    setup_vmcs_x64_state_intrinsics(mocks, guest_state);

    mocks.OnCallFunc(__vmwrite).Return(true);
    Call &launch_call = mocks.ExpectCallFunc(__vmlaunch).Return(false);
    mocks.OnCallFunc(__vmwrite).After(launch_call).Do(__vmwrite);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};
        std::vector<struct control_flow_path> cfg;

        setup_check_all_paths(cfg);

        for (const auto &sub_path : cfg)
            sub_path.setup();

        this->expect_exception([&] { vmcs.launch(host_state, guest_state); }, ""_ut_ree);
    });
}

void
vmcs_ut::test_launch_create_vmcs_region_failure()
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
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        auto ___ = gsl::finally([&]
        { g_new_throws_bad_alloc = 0; });

        g_new_throws_bad_alloc = STACK_SIZE * 2;

        this->expect_exception([&] { vmcs.launch(host_state, guest_state); }, ""_ut_bae);
    });
}

void
vmcs_ut::test_launch_clear_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        auto ___ = gsl::finally([&]
        { g_vmclear_fails = false; });

        g_vmclear_fails = true;
        this->expect_exception([&]{ vmcs.launch(host_state, guest_state); }, ""_ut_ree);
    });
}

void
vmcs_ut::test_launch_load_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    auto host_state = mocks.Mock<vmcs_intel_x64_state>();
    auto guest_state = mocks.Mock<vmcs_intel_x64_state>();

    setup_vmcs_intrinsics(mocks, mm);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        auto ___ = gsl::finally([&]
        { g_vmload_fails = false; });

        g_vmload_fails = true;
        this->expect_exception([&]{ vmcs.launch(host_state, guest_state); }, ""_ut_ree);
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

        this->expect_exception([&] { vmcs.promote(); }, ""_ut_ree);
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
        this->expect_exception([&] { vmcs.resume(); }, ""_ut_ree);
    });
}

void
vmcs_ut::test_get_vmcs_field()
{
    constexpr const auto name = "field";
    auto exists = true;

    this->expect_exception([&] { get_vmcs_field(0U, name, !exists); }, ""_ut_lee);

    g_vmcs_fields[0U] = 42U;
    this->expect_true(get_vmcs_field(0U, name, exists) == 42U);
}

void
vmcs_ut::test_get_vmcs_field_if_exists()
{
    constexpr const auto name = "field";

    auto exists = true;
    auto verbose = true;
    g_vmcs_fields[0U] = 42U;

    this->expect_true(get_vmcs_field_if_exists(0U, name, verbose, !exists) == 0U);
    this->expect_true(get_vmcs_field_if_exists(0U, name, verbose, exists) == 42U);
}

void
vmcs_ut::test_set_vmcs_field()
{
    constexpr const auto name("field");
    auto exists = true;
    g_vmcs_fields[0U] = 0U;

    this->expect_exception([&] { set_vmcs_field(1U, 0U, name, !exists); }, ""_ut_lee);
    this->expect_true(g_vmcs_fields[0U] == 0U);

    this->expect_no_exception([&] { set_vmcs_field(1U, 0U, name, exists); });
    this->expect_true(g_vmcs_fields[0U] == 1U);
}

void
vmcs_ut::test_set_vmcs_field_if_exists()
{
    constexpr const auto name("field");
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
vmcs_ut::test_set_vm_control()
{
    constexpr const auto name = "control";
    auto exists = true;
    auto mask = 0x0000000000000040UL;
    auto ctls_addr = 0UL;
    auto msr_addr = 0U;

    this->expect_exception([&] { set_vm_control(1UL, msr_addr, ctls_addr, name, mask, !exists); }, ""_ut_lee);

    g_msrs[msr_addr] = ~mask;
    this->expect_no_exception([&] { set_vm_control(0UL, msr_addr, ctls_addr, name, mask, exists); });
    this->expect_true((g_vmcs_fields[ctls_addr] & mask) == 0UL);

    g_msrs[msr_addr] = mask;
    this->expect_exception([&] { set_vm_control(0UL, msr_addr, ctls_addr, name, mask, exists); }, ""_ut_lee);

    g_msrs[msr_addr] = mask << 32;
    this->expect_no_exception([&] { set_vm_control(1UL, msr_addr, ctls_addr, name, mask, exists); });
    this->expect_true((g_vmcs_fields[ctls_addr] & mask) != 0UL);

    g_msrs[msr_addr] = ~(mask << 32);
    this->expect_exception([&] { set_vm_control(1UL, msr_addr, ctls_addr, name, mask, exists); }, ""_ut_lee);
}

void
vmcs_ut::test_set_vm_control_if_allowed()
{
    constexpr const auto name = "control";
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
vmcs_ut::test_set_vm_function_control()
{
    constexpr const auto name = "control";
    auto exists = true;
    auto mask = 0x0000000000000040UL;
    auto ctls_addr = 0UL;
    auto msr_addr = 0U;

    this->expect_exception([&] { set_vm_function_control(true, msr_addr, ctls_addr, name, mask, !exists); }, ""_ut_lee);
    this->expect_no_exception([&] { set_vm_function_control(false, msr_addr, ctls_addr, name, mask, exists); });

    g_msrs[msr_addr] = mask;
    this->expect_no_exception([&] { set_vm_function_control(true, msr_addr, ctls_addr, name, mask, exists); });

    g_msrs[msr_addr] = ~mask;
    this->expect_exception([&] { set_vm_function_control(true, msr_addr, ctls_addr, name, mask, exists); }, ""_ut_lee);
}

void
vmcs_ut::test_set_vm_function_control_if_allowed()
{
    constexpr const auto name = "control";
    auto exists = true;
    auto verbose = true;
    auto mask = 0x0000000000000040UL;
    auto ctls_addr = 0UL;
    auto msr_addr = 0U;

    this->expect_no_exception([&] { set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, verbose, !exists); });
    this->expect_no_exception([&] { set_vm_function_control_if_allowed(false, msr_addr, ctls_addr, name, mask, verbose, exists); });

    g_msrs[msr_addr] = mask;
    this->expect_no_exception([&] { set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, verbose, exists); });

    g_msrs[msr_addr] = ~mask;
    this->expect_no_exception([&] { set_vm_function_control_if_allowed(true, msr_addr, ctls_addr, name, mask, verbose, exists); });
}

void
vmcs_ut::test_vmcs_vm_instruction_error_description()
{
    using namespace vmcs::vm_instruction_error;

    bool exists = true;

    this->expect_exception([&] { vm_instruction_error_description(0UL, !exists); }, ""_ut_lee);
    this->expect_true(vm_instruction_error_description(1UL, exists) == "VMCALL executed in VMX root operation"_s);
}

void
vmcs_ut::test_vmcs_vm_instruction_error_description_if_exists()
{
    using namespace vmcs::vm_instruction_error;

    bool exists = true;
    bool verbose = true;

    this->expect_no_exception([&] { vm_instruction_error_description_if_exists(0UL, verbose, !exists); });
    this->expect_true(vm_instruction_error_description_if_exists(0UL, verbose, !exists) == ""_s);
    this->expect_true(vm_instruction_error_description_if_exists(1UL, verbose, exists) == "VMCALL executed in VMX root operation"_s);
}

void
vmcs_ut::test_vmcs_exit_reason_basic_exit_reason_description()
{
    using namespace vmcs::exit_reason;

    bool exists = true;

    this->expect_exception([&] { basic_exit_reason::basic_exit_reason_description(0UL, !exists); }, ""_ut_lee);
    this->expect_true(basic_exit_reason::basic_exit_reason_description(basic_exit_reason::pause, exists) == "pause"_s);
}

void
vmcs_ut::test_vmcs_exit_reason_basic_exit_reason_description_if_exists()
{
    using namespace vmcs::exit_reason;

    bool exists = true;
    bool verbose = true;

    this->expect_no_exception([&] { basic_exit_reason::basic_exit_reason_description_if_exists(0UL, verbose, !exists); });
    this->expect_true(basic_exit_reason::basic_exit_reason_description_if_exists(0UL, verbose, !exists) == ""_s);
    this->expect_true(basic_exit_reason::basic_exit_reason_description_if_exists(basic_exit_reason::pause, verbose, exists) == "pause"_s);
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
vmcs_ut::test_vmcs_address_of_io_bitmap_a()
{
    this->expect_true(vmcs::address_of_io_bitmap_a::exists());

    vmcs::address_of_io_bitmap_a::set(1UL);
    this->expect_true(vmcs::address_of_io_bitmap_a::get() == 1UL);

    vmcs::address_of_io_bitmap_a::set_if_exists(0UL);
    this->expect_true(vmcs::address_of_io_bitmap_a::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_address_of_io_bitmap_b()
{
    this->expect_true(vmcs::address_of_io_bitmap_b::exists());

    vmcs::address_of_io_bitmap_b::set(1UL);
    this->expect_true(vmcs::address_of_io_bitmap_b::get() == 1UL);

    vmcs::address_of_io_bitmap_b::set_if_exists(0UL);
    this->expect_true(vmcs::address_of_io_bitmap_b::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_address_of_msr_bitmaps()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::mask);
    this->expect_true(vmcs::address_of_msr_bitmaps::exists());

    vmcs::address_of_msr_bitmaps::set(1UL);
    this->expect_true(vmcs::address_of_msr_bitmaps::get() == 1UL);

    vmcs::address_of_msr_bitmaps::set_if_exists(0UL);
    this->expect_true(vmcs::address_of_msr_bitmaps::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_vm_exit_msr_store_address()
{
    this->expect_true(vmcs::vm_exit_msr_store_address::exists());

    vmcs::vm_exit_msr_store_address::set(1UL);
    this->expect_true(vmcs::vm_exit_msr_store_address::get() == 1UL);

    vmcs::vm_exit_msr_store_address::set_if_exists(0UL);
    this->expect_true(vmcs::vm_exit_msr_store_address::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_vm_exit_msr_load_address()
{
    this->expect_true(vmcs::vm_exit_msr_load_address::exists());

    vmcs::vm_exit_msr_load_address::set(1UL);
    this->expect_true(vmcs::vm_exit_msr_load_address::get() == 1UL);

    vmcs::vm_exit_msr_load_address::set_if_exists(0UL);
    this->expect_true(vmcs::vm_exit_msr_load_address::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_vm_entry_msr_load_address()
{
    this->expect_true(vmcs::vm_entry_msr_load_address::exists());

    vmcs::vm_entry_msr_load_address::set(1UL);
    this->expect_true(vmcs::vm_entry_msr_load_address::get() == 1UL);

    vmcs::vm_entry_msr_load_address::set_if_exists(0UL);
    this->expect_true(vmcs::vm_entry_msr_load_address::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_executive_vmcs_pointer()
{
    this->expect_true(vmcs::executive_vmcs_pointer::exists());

    vmcs::executive_vmcs_pointer::set(1UL);
    this->expect_true(vmcs::executive_vmcs_pointer::get() == 1UL);

    vmcs::executive_vmcs_pointer::set_if_exists(0UL);
    this->expect_true(vmcs::executive_vmcs_pointer::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_pml_address()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_pml::mask);
    this->expect_true(vmcs::pml_address::exists());

    vmcs::pml_address::set(1UL);
    this->expect_true(vmcs::pml_address::get() == 1UL);

    vmcs::pml_address::set_if_exists(0UL);
    this->expect_true(vmcs::pml_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_pml::mask);
    this->expect_false(vmcs::pml_address::exists());

    this->expect_exception([&] { vmcs::pml_address::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::pml_address::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::pml_address::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::pml_address::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::pml_address::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_tsc_offset()
{
    this->expect_true(vmcs::tsc_offset::exists());

    vmcs::tsc_offset::set(1UL);
    this->expect_true(vmcs::tsc_offset::get() == 1UL);

    vmcs::tsc_offset::set_if_exists(0UL);
    this->expect_true(vmcs::tsc_offset::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_virtual_apic_address()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::mask);
    this->expect_true(vmcs::virtual_apic_address::exists());

    vmcs::virtual_apic_address::set(1UL);
    this->expect_true(vmcs::virtual_apic_address::get() == 1UL);

    vmcs::virtual_apic_address::set_if_exists(0UL);
    this->expect_true(vmcs::virtual_apic_address::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_apic_access_address()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::mask);
    this->expect_true(vmcs::apic_access_address::exists());

    vmcs::apic_access_address::set(1UL);
    this->expect_true(vmcs::apic_access_address::get() == 1UL);

    vmcs::apic_access_address::set_if_exists(0UL);
    this->expect_true(vmcs::apic_access_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtualize_apic_accesses::mask);
    this->expect_false(vmcs::apic_access_address::exists());

    this->expect_exception([&] { vmcs::apic_access_address::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::apic_access_address::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::apic_access_address::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::apic_access_address::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::apic_access_address::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_posted_interrupt_descriptor_address()
{
    pin_ctl_allow1(msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask);
    this->expect_true(vmcs::posted_interrupt_descriptor_address::exists());

    vmcs::posted_interrupt_descriptor_address::set(1UL);
    this->expect_true(vmcs::posted_interrupt_descriptor_address::get() == 1UL);

    vmcs::posted_interrupt_descriptor_address::set_if_exists(0UL);
    this->expect_true(vmcs::posted_interrupt_descriptor_address::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_vm_function_controls()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    this->expect_true(vmcs::vm_function_controls::exists());

    vmcs::vm_function_controls::set(1UL);
    this->expect_true(vmcs::vm_function_controls::get() == 1UL);

    vmcs::vm_function_controls::set_if_exists(0UL);
    this->expect_true(vmcs::vm_function_controls::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    this->expect_false(vmcs::vm_function_controls::exists());

    this->expect_exception([&] { vmcs::vm_function_controls::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::vm_function_controls::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::vm_function_controls::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::vm_function_controls::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::vm_function_controls::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_vm_function_controls_eptp_switching()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    vmfunc_ctl_allow1(msrs::ia32_vmx_vmfunc::eptp_switching::mask);

    vmcs::vm_function_controls::eptp_switching::enable();
    this->expect_true(vmcs::vm_function_controls::eptp_switching::is_enabled());

    vmcs::vm_function_controls::eptp_switching::disable();
    this->expect_true(vmcs::vm_function_controls::eptp_switching::is_disabled());

    vmcs::vm_function_controls::eptp_switching::enable_if_allowed();
    this->expect_true(vmcs::vm_function_controls::eptp_switching::is_enabled_if_exists());

    vmcs::vm_function_controls::eptp_switching::disable_if_allowed();
    this->expect_true(vmcs::vm_function_controls::eptp_switching::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_function_controls_reserved()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);

    vmcs::vm_function_controls::reserved::set(0xEU);
    this->expect_true(vmcs::vm_function_controls::reserved::get() == 0xEU);

    vmcs::vm_function_controls::reserved::set_if_exists(0x0U);
    this->expect_true(vmcs::vm_function_controls::reserved::get_if_exists() == 0x0U);
}

void
vmcs_ut::test_vmcs_ept_pointer()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);
    this->expect_true(vmcs::ept_pointer::exists());

    vmcs::ept_pointer::set(1UL);
    this->expect_true(vmcs::ept_pointer::get() == 1UL);

    vmcs::ept_pointer::set_if_exists(0UL);
    this->expect_true(vmcs::ept_pointer::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);
    this->expect_false(vmcs::ept_pointer::exists());

    this->expect_exception([&] { vmcs::ept_pointer::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::ept_pointer::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::ept_pointer::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::ept_pointer::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::ept_pointer::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_ept_pointer_memory_type()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    vmcs::ept_pointer::memory_type::set(0UL);
    this->expect_true(vmcs::ept_pointer::memory_type::get() == vmcs::ept_pointer::memory_type::uncacheable);

    vmcs::ept_pointer::memory_type::set_if_exists(6UL);
    this->expect_true(vmcs::ept_pointer::memory_type::get_if_exists() == vmcs::ept_pointer::memory_type::write_back);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);
    this->expect_exception([&] { vmcs::ept_pointer::memory_type::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::ept_pointer::memory_type::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::ept_pointer::memory_type::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::ept_pointer::memory_type::get_if_exists(); });
}

void
vmcs_ut::test_vmcs_ept_pointer_page_walk_length_minus_one()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    vmcs::ept_pointer::page_walk_length_minus_one::set(2UL);
    this->expect_true(vmcs::ept_pointer::page_walk_length_minus_one::get() == 2UL);

    vmcs::ept_pointer::page_walk_length_minus_one::set_if_exists(1UL);
    this->expect_true(vmcs::ept_pointer::page_walk_length_minus_one::get_if_exists() == 1UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);
    this->expect_exception([&] { vmcs::ept_pointer::page_walk_length_minus_one::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::ept_pointer::page_walk_length_minus_one::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::ept_pointer::page_walk_length_minus_one::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::ept_pointer::page_walk_length_minus_one::get_if_exists(); });
}

void
vmcs_ut::test_vmcs_ept_pointer_accessed_and_dirty_flags()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    vmcs::ept_pointer::accessed_and_dirty_flags::enable();
    this->expect_true(vmcs::ept_pointer::accessed_and_dirty_flags::is_enabled());

    vmcs::ept_pointer::accessed_and_dirty_flags::disable();
    this->expect_true(vmcs::ept_pointer::accessed_and_dirty_flags::is_disabled());

    vmcs::ept_pointer::accessed_and_dirty_flags::enable_if_exists();
    this->expect_true(vmcs::ept_pointer::accessed_and_dirty_flags::is_enabled_if_exists());

    vmcs::ept_pointer::accessed_and_dirty_flags::disable_if_exists();
    this->expect_true(vmcs::ept_pointer::accessed_and_dirty_flags::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_ept_pointer_reserved()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask);

    vmcs::ept_pointer::reserved::set(0x80U);
    this->expect_true(vmcs::ept_pointer::reserved::get() == 0x80U);

    vmcs::ept_pointer::reserved::set_if_exists(0x0U);
    this->expect_true(vmcs::ept_pointer::reserved::get_if_exists() == 0x0U);
}

void
vmcs_ut::test_vmcs_eoi_exit_bitmap_0()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    this->expect_true(vmcs::eoi_exit_bitmap_0::exists());

    vmcs::eoi_exit_bitmap_0::set(1UL);
    this->expect_true(vmcs::eoi_exit_bitmap_0::get() == 1UL);

    vmcs::eoi_exit_bitmap_0::set_if_exists(0UL);
    this->expect_true(vmcs::eoi_exit_bitmap_0::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    this->expect_false(vmcs::eoi_exit_bitmap_0::exists());

    this->expect_exception([&] { vmcs::eoi_exit_bitmap_0::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::eoi_exit_bitmap_0::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::eoi_exit_bitmap_0::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::eoi_exit_bitmap_0::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::eoi_exit_bitmap_0::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_eoi_exit_bitmap_1()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    this->expect_true(vmcs::eoi_exit_bitmap_1::exists());

    vmcs::eoi_exit_bitmap_1::set(1UL);
    this->expect_true(vmcs::eoi_exit_bitmap_1::get() == 1UL);

    vmcs::eoi_exit_bitmap_1::set_if_exists(0UL);
    this->expect_true(vmcs::eoi_exit_bitmap_1::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    this->expect_false(vmcs::eoi_exit_bitmap_1::exists());

    this->expect_exception([&] { vmcs::eoi_exit_bitmap_1::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::eoi_exit_bitmap_1::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::eoi_exit_bitmap_1::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::eoi_exit_bitmap_1::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::eoi_exit_bitmap_1::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_eoi_exit_bitmap_2()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    this->expect_true(vmcs::eoi_exit_bitmap_2::exists());

    vmcs::eoi_exit_bitmap_2::set(1UL);
    this->expect_true(vmcs::eoi_exit_bitmap_2::get() == 1UL);

    vmcs::eoi_exit_bitmap_2::set_if_exists(0UL);
    this->expect_true(vmcs::eoi_exit_bitmap_2::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    this->expect_false(vmcs::eoi_exit_bitmap_2::exists());

    this->expect_exception([&] { vmcs::eoi_exit_bitmap_2::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::eoi_exit_bitmap_2::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::eoi_exit_bitmap_2::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::eoi_exit_bitmap_2::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::eoi_exit_bitmap_2::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_eoi_exit_bitmap_3()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    this->expect_true(vmcs::eoi_exit_bitmap_3::exists());

    vmcs::eoi_exit_bitmap_3::set(1UL);
    this->expect_true(vmcs::eoi_exit_bitmap_3::get() == 1UL);

    vmcs::eoi_exit_bitmap_3::set_if_exists(0UL);
    this->expect_true(vmcs::eoi_exit_bitmap_3::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
    this->expect_false(vmcs::eoi_exit_bitmap_3::exists());

    this->expect_exception([&] { vmcs::eoi_exit_bitmap_3::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::eoi_exit_bitmap_3::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::eoi_exit_bitmap_3::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::eoi_exit_bitmap_3::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::eoi_exit_bitmap_3::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_eptp_list_address()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    vmfunc_ctl_allow1(msrs::ia32_vmx_vmfunc::eptp_switching::mask);
    this->expect_true(vmcs::eptp_list_address::exists());

    vmcs::eptp_list_address::set(1UL);
    this->expect_true(vmcs::eptp_list_address::get() == 1UL);

    vmcs::eptp_list_address::set_if_exists(0UL);
    this->expect_true(vmcs::eptp_list_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
    this->expect_false(vmcs::eptp_list_address::exists());

    this->expect_exception([&] { vmcs::eptp_list_address::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::eptp_list_address::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::eptp_list_address::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::eptp_list_address::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::eptp_list_address::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_vmread_bitmap_address()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
    this->expect_true(vmcs::vmread_bitmap_address::exists());

    vmcs::vmread_bitmap_address::set(1UL);
    this->expect_true(vmcs::vmread_bitmap_address::get() == 1UL);

    vmcs::vmread_bitmap_address::set_if_exists(0UL);
    this->expect_true(vmcs::vmread_bitmap_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
    this->expect_false(vmcs::vmread_bitmap_address::exists());

    this->expect_exception([&] { vmcs::vmread_bitmap_address::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::vmread_bitmap_address::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::vmread_bitmap_address::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::vmread_bitmap_address::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::vmread_bitmap_address::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_vmwrite_bitmap_address()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
    this->expect_true(vmcs::vmwrite_bitmap_address::exists());

    vmcs::vmwrite_bitmap_address::set(1UL);
    this->expect_true(vmcs::vmwrite_bitmap_address::get() == 1UL);

    vmcs::vmwrite_bitmap_address::set_if_exists(0UL);
    this->expect_true(vmcs::vmwrite_bitmap_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
    this->expect_false(vmcs::vmwrite_bitmap_address::exists());

    this->expect_exception([&] { vmcs::vmwrite_bitmap_address::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::vmwrite_bitmap_address::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::vmwrite_bitmap_address::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::vmwrite_bitmap_address::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::vmwrite_bitmap_address::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_virtualization_exception_information_address()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask);
    this->expect_true(vmcs::virtualization_exception_information_address::exists());

    vmcs::virtualization_exception_information_address::set(1UL);
    this->expect_true(vmcs::virtualization_exception_information_address::get() == 1UL);

    vmcs::virtualization_exception_information_address::set_if_exists(0UL);
    this->expect_true(vmcs::virtualization_exception_information_address::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask);
    this->expect_false(vmcs::virtualization_exception_information_address::exists());

    this->expect_exception([&] { vmcs::virtualization_exception_information_address::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::virtualization_exception_information_address::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::virtualization_exception_information_address::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::virtualization_exception_information_address::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::virtualization_exception_information_address::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_xss_exiting_bitmap()
{
    proc_ctl_allow1(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
    proc_ctl2_allow1(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::mask);
    this->expect_true(vmcs::xss_exiting_bitmap::exists());

    vmcs::xss_exiting_bitmap::set(1UL);
    this->expect_true(vmcs::xss_exiting_bitmap::get() == 1UL);

    vmcs::xss_exiting_bitmap::set_if_exists(0UL);
    this->expect_true(vmcs::xss_exiting_bitmap::get_if_exists() == 0UL);

    proc_ctl2_disallow1(msrs::ia32_vmx_procbased_ctls2::enable_xsaves_xrstors::mask);
    this->expect_false(vmcs::xss_exiting_bitmap::exists());

    this->expect_exception([&] { vmcs::xss_exiting_bitmap::set(42U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::xss_exiting_bitmap::get(); }, ""_ut_lee);

    this->expect_no_exception([&] { vmcs::xss_exiting_bitmap::set_if_exists(42U); });
    this->expect_no_exception([&] { vmcs::xss_exiting_bitmap::get_if_exists(); });
    this->expect_true(g_vmcs_fields[vmcs::xss_exiting_bitmap::addr] == 0UL);
}

void
vmcs_ut::test_vmcs_vmcs_link_pointer()
{
    this->expect_true(vmcs::vmcs_link_pointer::exists());

    vmcs::vmcs_link_pointer::set(1UL);
    this->expect_true(vmcs::vmcs_link_pointer::get() == 1UL);

    vmcs::vmcs_link_pointer::set_if_exists(0UL);
    this->expect_true(vmcs::vmcs_link_pointer::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl()
{
    this->expect_true(vmcs::guest_ia32_debugctl::exists());

    vmcs::guest_ia32_debugctl::set(1UL);
    this->expect_true(vmcs::guest_ia32_debugctl::get() == 1UL);

    vmcs::guest_ia32_debugctl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_debugctl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_lbr()
{
    vmcs::guest_ia32_debugctl::lbr::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::lbr::is_enabled());

    vmcs::guest_ia32_debugctl::lbr::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::lbr::is_disabled());

    vmcs::guest_ia32_debugctl::lbr::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::lbr::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::lbr::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::lbr::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_btf()
{
    vmcs::guest_ia32_debugctl::btf::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::btf::is_enabled());

    vmcs::guest_ia32_debugctl::btf::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::btf::is_disabled());

    vmcs::guest_ia32_debugctl::btf::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::btf::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::btf::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::btf::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_tr()
{
    vmcs::guest_ia32_debugctl::tr::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::tr::is_enabled());

    vmcs::guest_ia32_debugctl::tr::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::tr::is_disabled());

    vmcs::guest_ia32_debugctl::tr::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::tr::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::tr::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::tr::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_bts()
{
    vmcs::guest_ia32_debugctl::bts::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::bts::is_enabled());

    vmcs::guest_ia32_debugctl::bts::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::bts::is_disabled());

    vmcs::guest_ia32_debugctl::bts::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::bts::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::bts::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::bts::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_btint()
{
    vmcs::guest_ia32_debugctl::btint::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::btint::is_enabled());

    vmcs::guest_ia32_debugctl::btint::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::btint::is_disabled());

    vmcs::guest_ia32_debugctl::btint::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::btint::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::btint::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::btint::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_bt_off_os()
{
    vmcs::guest_ia32_debugctl::bt_off_os::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::bt_off_os::is_enabled());

    vmcs::guest_ia32_debugctl::bt_off_os::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::bt_off_os::is_disabled());

    vmcs::guest_ia32_debugctl::bt_off_os::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::bt_off_os::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::bt_off_os::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::bt_off_os::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_bt_off_user()
{
    vmcs::guest_ia32_debugctl::bt_off_user::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::bt_off_user::is_enabled());

    vmcs::guest_ia32_debugctl::bt_off_user::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::bt_off_user::is_disabled());

    vmcs::guest_ia32_debugctl::bt_off_user::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::bt_off_user::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::bt_off_user::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::bt_off_user::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_freeze_lbrs_on_pmi()
{
    vmcs::guest_ia32_debugctl::freeze_lbrs_on_pmi::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_lbrs_on_pmi::is_enabled());

    vmcs::guest_ia32_debugctl::freeze_lbrs_on_pmi::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_lbrs_on_pmi::is_disabled());

    vmcs::guest_ia32_debugctl::freeze_lbrs_on_pmi::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_lbrs_on_pmi::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::freeze_lbrs_on_pmi::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_lbrs_on_pmi::is_disabled_if_exists());
}


void
vmcs_ut::test_vmcs_guest_ia32_debugctl_freeze_perfmon_on_pmi()
{
    vmcs::guest_ia32_debugctl::freeze_perfmon_on_pmi::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_perfmon_on_pmi::is_enabled());

    vmcs::guest_ia32_debugctl::freeze_perfmon_on_pmi::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_perfmon_on_pmi::is_disabled());

    vmcs::guest_ia32_debugctl::freeze_perfmon_on_pmi::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_perfmon_on_pmi::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::freeze_perfmon_on_pmi::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_perfmon_on_pmi::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_enable_uncore_pmi()
{
    vmcs::guest_ia32_debugctl::enable_uncore_pmi::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::enable_uncore_pmi::is_enabled());

    vmcs::guest_ia32_debugctl::enable_uncore_pmi::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::enable_uncore_pmi::is_disabled());

    vmcs::guest_ia32_debugctl::enable_uncore_pmi::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::enable_uncore_pmi::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::enable_uncore_pmi::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::enable_uncore_pmi::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_freeze_while_smm()
{
    vmcs::guest_ia32_debugctl::freeze_while_smm::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_while_smm::is_enabled());

    vmcs::guest_ia32_debugctl::freeze_while_smm::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_while_smm::is_disabled());

    vmcs::guest_ia32_debugctl::freeze_while_smm::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_while_smm::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::freeze_while_smm::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::freeze_while_smm::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_rtm_debug()
{
    vmcs::guest_ia32_debugctl::rtm_debug::enable();
    this->expect_true(vmcs::guest_ia32_debugctl::rtm_debug::is_enabled());

    vmcs::guest_ia32_debugctl::rtm_debug::disable();
    this->expect_true(vmcs::guest_ia32_debugctl::rtm_debug::is_disabled());

    vmcs::guest_ia32_debugctl::rtm_debug::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::rtm_debug::is_enabled_if_exists());

    vmcs::guest_ia32_debugctl::rtm_debug::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_debugctl::rtm_debug::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_debugctl_reserved()
{
    vmcs::guest_ia32_debugctl::reserved::set(0xCU);
    this->expect_true(vmcs::guest_ia32_debugctl::reserved::get() == 0xCU);

    vmcs::guest_ia32_debugctl::reserved::set_if_exists(0x0U);
    this->expect_true(vmcs::guest_ia32_debugctl::reserved::get_if_exists() == 0x0U);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;
    this->expect_true(vmcs::guest_ia32_pat::exists());

    vmcs::guest_ia32_pat::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::get() == 1UL);

    vmcs::guest_ia32_pat::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa0()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa0::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa0::get() == 1UL);

    vmcs::guest_ia32_pat::pa0::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa0::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa0_memory_type()
{
    using namespace vmcs::guest_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    pa0::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa0::memory_type::get() == x64::memory_type::uncacheable);

    pa0::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa0::memory_type::get() == x64::memory_type::write_combining);

    pa0::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa0::memory_type::get() == x64::memory_type::write_through);

    pa0::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa0::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa0::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa0::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa0::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa0::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa0_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa0::reserved::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa0::reserved::get() == 1UL);

    vmcs::guest_ia32_pat::pa0::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa0::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa1()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa1::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa1::get() == 1UL);

    vmcs::guest_ia32_pat::pa1::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa1::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa1_memory_type()
{
    using namespace vmcs::guest_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    pa1::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa1::memory_type::get() == x64::memory_type::uncacheable);

    pa1::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa1::memory_type::get() == x64::memory_type::write_combining);

    pa1::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa1::memory_type::get() == x64::memory_type::write_through);

    pa1::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa1::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa1::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa1::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa1::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa1::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa1_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa1::reserved::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa1::reserved::get() == 1UL);

    vmcs::guest_ia32_pat::pa1::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa1::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa2()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa2::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa2::get() == 1UL);

    vmcs::guest_ia32_pat::pa2::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa2::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa2_memory_type()
{
    using namespace vmcs::guest_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    pa2::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa2::memory_type::get() == x64::memory_type::uncacheable);

    pa2::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa2::memory_type::get() == x64::memory_type::write_combining);

    pa2::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa2::memory_type::get() == x64::memory_type::write_through);

    pa2::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa2::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa2::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa2::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa2::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa2::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa2_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa2::reserved::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa2::reserved::get() == 1UL);

    vmcs::guest_ia32_pat::pa2::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa2::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa3()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa3::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa3::get() == 1UL);

    vmcs::guest_ia32_pat::pa3::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa3::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa3_memory_type()
{
    using namespace vmcs::guest_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    pa3::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa3::memory_type::get() == x64::memory_type::uncacheable);

    pa3::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa3::memory_type::get() == x64::memory_type::write_combining);

    pa3::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa3::memory_type::get() == x64::memory_type::write_through);

    pa3::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa3::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa3::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa3::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa3::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa3::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa3_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa3::reserved::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa3::reserved::get() == 1UL);

    vmcs::guest_ia32_pat::pa3::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa3::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa4()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa4::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa4::get() == 1UL);

    vmcs::guest_ia32_pat::pa4::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa4::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa4_memory_type()
{
    using namespace vmcs::guest_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    pa4::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa4::memory_type::get() == x64::memory_type::uncacheable);

    pa4::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa4::memory_type::get() == x64::memory_type::write_combining);

    pa4::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa4::memory_type::get() == x64::memory_type::write_through);

    pa4::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa4::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa4::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa4::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa4::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa4::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa4_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa4::reserved::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa4::reserved::get() == 1UL);

    vmcs::guest_ia32_pat::pa4::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa4::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa5()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa5::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa5::get() == 1UL);

    vmcs::guest_ia32_pat::pa5::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa5::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa5_memory_type()
{
    using namespace vmcs::guest_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    pa5::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa5::memory_type::get() == x64::memory_type::uncacheable);

    pa5::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa5::memory_type::get() == x64::memory_type::write_combining);

    pa5::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa5::memory_type::get() == x64::memory_type::write_through);

    pa5::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa5::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa5::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa5::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa5::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa5::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa5_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa5::reserved::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa5::reserved::get() == 1UL);

    vmcs::guest_ia32_pat::pa5::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa5::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa6()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa6::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa6::get() == 1UL);

    vmcs::guest_ia32_pat::pa6::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa6::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa6_memory_type()
{
    using namespace vmcs::guest_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    pa6::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa6::memory_type::get() == x64::memory_type::uncacheable);

    pa6::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa6::memory_type::get() == x64::memory_type::write_combining);

    pa6::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa6::memory_type::get() == x64::memory_type::write_through);

    pa6::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa6::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa6::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa6::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa6::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa6::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa6_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa6::reserved::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa6::reserved::get() == 1UL);

    vmcs::guest_ia32_pat::pa6::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa6::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa7()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa7::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa7::get() == 1UL);

    vmcs::guest_ia32_pat::pa7::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa7::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa7_memory_type()
{
    using namespace vmcs::guest_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    pa7::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa7::memory_type::get() == x64::memory_type::uncacheable);

    pa7::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa7::memory_type::get() == x64::memory_type::write_combining);

    pa7::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa7::memory_type::get() == x64::memory_type::write_through);

    pa7::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa7::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa7::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa7::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa7::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa7::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_guest_ia32_pat_pa7_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_pat::mask << 32;

    vmcs::guest_ia32_pat::pa7::reserved::set(1UL);
    this->expect_true(vmcs::guest_ia32_pat::pa7::reserved::get() == 1UL);

    vmcs::guest_ia32_pat::pa7::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_pat::pa7::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_efer()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;
    this->expect_true(vmcs::guest_ia32_efer::exists());

    vmcs::guest_ia32_efer::set(1UL);
    this->expect_true(vmcs::guest_ia32_efer::get() == 1UL);

    vmcs::guest_ia32_efer::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_efer::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_efer_sce()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    vmcs::guest_ia32_efer::sce::enable();
    this->expect_true(vmcs::guest_ia32_efer::sce::is_enabled());

    vmcs::guest_ia32_efer::sce::disable();
    this->expect_true(vmcs::guest_ia32_efer::sce::is_disabled());

    vmcs::guest_ia32_efer::sce::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_efer::sce::is_enabled_if_exists());

    vmcs::guest_ia32_efer::sce::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_efer::sce::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_efer_lme()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    vmcs::guest_ia32_efer::lme::enable();
    this->expect_true(vmcs::guest_ia32_efer::lme::is_enabled());

    vmcs::guest_ia32_efer::lme::disable();
    this->expect_true(vmcs::guest_ia32_efer::lme::is_disabled());

    vmcs::guest_ia32_efer::lme::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_efer::lme::is_enabled_if_exists());

    vmcs::guest_ia32_efer::lme::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_efer::lme::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_efer_lma()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    vmcs::guest_ia32_efer::lma::enable();
    this->expect_true(vmcs::guest_ia32_efer::lma::is_enabled());

    vmcs::guest_ia32_efer::lma::disable();
    this->expect_true(vmcs::guest_ia32_efer::lma::is_disabled());

    vmcs::guest_ia32_efer::lma::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_efer::lma::is_enabled_if_exists());

    vmcs::guest_ia32_efer::lma::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_efer::lma::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_efer_nxe()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    vmcs::guest_ia32_efer::nxe::enable();
    this->expect_true(vmcs::guest_ia32_efer::nxe::is_enabled());

    vmcs::guest_ia32_efer::nxe::disable();
    this->expect_true(vmcs::guest_ia32_efer::nxe::is_disabled());

    vmcs::guest_ia32_efer::nxe::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_efer::nxe::is_enabled_if_exists());

    vmcs::guest_ia32_efer::nxe::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_efer::nxe::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_efer_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_efer::mask << 32;

    vmcs::guest_ia32_efer::reserved::set(0xEU);
    this->expect_true(vmcs::guest_ia32_efer::reserved::get() == 0xEU);

    vmcs::guest_ia32_efer::reserved::set_if_exists(0x0U);
    this->expect_true(vmcs::guest_ia32_efer::reserved::get_if_exists() == 0x0U);
}

void
vmcs_ut::test_vmcs_guest_ia32_perf_global_ctrl()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask << 32;
    this->expect_true(vmcs::guest_ia32_perf_global_ctrl::exists());

    vmcs::guest_ia32_perf_global_ctrl::set(1UL);
    this->expect_true(vmcs::guest_ia32_perf_global_ctrl::get() == 1UL);

    vmcs::guest_ia32_perf_global_ctrl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_perf_global_ctrl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_perf_global_ctrl_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= msrs::ia32_vmx_true_entry_ctls::load_ia32_perf_global_ctrl::mask << 32;
    this->expect_true(vmcs::guest_ia32_perf_global_ctrl::exists());

    vmcs::guest_ia32_perf_global_ctrl::reserved::set(0xCUL);
    this->expect_true(vmcs::guest_ia32_perf_global_ctrl::reserved::get() == 0xCUL);

    vmcs::guest_ia32_perf_global_ctrl::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_perf_global_ctrl::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_pdpte0()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    this->expect_true(vmcs::guest_pdpte0::exists());

    vmcs::guest_pdpte0::set(1UL);
    this->expect_true(vmcs::guest_pdpte0::get() == 1UL);

    vmcs::guest_pdpte0::set_if_exists(0UL);
    this->expect_true(vmcs::guest_pdpte0::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_pdpte0_present()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte0::present::enable();
    this->expect_true(vmcs::guest_pdpte0::present::is_enabled());

    vmcs::guest_pdpte0::present::disable();
    this->expect_true(vmcs::guest_pdpte0::present::is_disabled());

    vmcs::guest_pdpte0::present::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte0::present::is_enabled_if_exists());

    vmcs::guest_pdpte0::present::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte0::present::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte0_reserved()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte0::reserved::set(6U);
    this->expect_true(vmcs::guest_pdpte0::reserved::get() == 6U);

    vmcs::guest_pdpte0::reserved::set_if_exists(0x8000000000000000U);
    this->expect_true(vmcs::guest_pdpte0::reserved::get_if_exists() == 0x8000000000000000U);
}

void
vmcs_ut::test_vmcs_guest_pdpte0_pwt()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte0::pwt::enable();
    this->expect_true(vmcs::guest_pdpte0::pwt::is_enabled());

    vmcs::guest_pdpte0::pwt::disable();
    this->expect_true(vmcs::guest_pdpte0::pwt::is_disabled());

    vmcs::guest_pdpte0::pwt::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte0::pwt::is_enabled_if_exists());

    vmcs::guest_pdpte0::pwt::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte0::pwt::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte0_pcd()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte0::pcd::enable();
    this->expect_true(vmcs::guest_pdpte0::pcd::is_enabled());

    vmcs::guest_pdpte0::pcd::disable();
    this->expect_true(vmcs::guest_pdpte0::pcd::is_disabled());

    vmcs::guest_pdpte0::pcd::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte0::pcd::is_enabled_if_exists());

    vmcs::guest_pdpte0::pcd::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte0::pcd::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte0_page_directory_addr()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;
    g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;

    vmcs::guest_pdpte0::page_directory_addr::set(0x100000000U);
    this->expect_true(vmcs::guest_pdpte0::page_directory_addr::get() == 0x100000000UL);

    vmcs::guest_pdpte0::page_directory_addr::set_if_exists(0x0U);
    this->expect_true(vmcs::guest_pdpte0::page_directory_addr::get_if_exists() == 0x0U);
}

void
vmcs_ut::test_vmcs_guest_pdpte1()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    this->expect_true(vmcs::guest_pdpte1::exists());

    vmcs::guest_pdpte1::set(1UL);
    this->expect_true(vmcs::guest_pdpte1::get() == 1UL);

    vmcs::guest_pdpte1::set_if_exists(0UL);
    this->expect_true(vmcs::guest_pdpte1::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_pdpte1_present()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte1::present::enable();
    this->expect_true(vmcs::guest_pdpte1::present::is_enabled());

    vmcs::guest_pdpte1::present::disable();
    this->expect_true(vmcs::guest_pdpte1::present::is_disabled());

    vmcs::guest_pdpte1::present::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte1::present::is_enabled_if_exists());

    vmcs::guest_pdpte1::present::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte1::present::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte1_reserved()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte1::reserved::set(6U);
    this->expect_true(vmcs::guest_pdpte1::reserved::get() == 6U);

    vmcs::guest_pdpte1::reserved::set_if_exists(0x8000000000000000U);
    this->expect_true(vmcs::guest_pdpte1::reserved::get_if_exists() == 0x8000000000000000U);
}

void
vmcs_ut::test_vmcs_guest_pdpte1_pwt()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte1::pwt::enable();
    this->expect_true(vmcs::guest_pdpte1::pwt::is_enabled());

    vmcs::guest_pdpte1::pwt::disable();
    this->expect_true(vmcs::guest_pdpte1::pwt::is_disabled());

    vmcs::guest_pdpte1::pwt::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte1::pwt::is_enabled_if_exists());

    vmcs::guest_pdpte1::pwt::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte1::pwt::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte1_pcd()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte1::pcd::enable();
    this->expect_true(vmcs::guest_pdpte1::pcd::is_enabled());

    vmcs::guest_pdpte1::pcd::disable();
    this->expect_true(vmcs::guest_pdpte1::pcd::is_disabled());

    vmcs::guest_pdpte1::pcd::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte1::pcd::is_enabled_if_exists());

    vmcs::guest_pdpte1::pcd::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte1::pcd::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte1_page_directory_addr()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;
    g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;

    vmcs::guest_pdpte1::page_directory_addr::set(0x100000000U);
    this->expect_true(vmcs::guest_pdpte1::page_directory_addr::get() == 0x100000000UL);

    vmcs::guest_pdpte1::page_directory_addr::set_if_exists(0x0U);
    this->expect_true(vmcs::guest_pdpte1::page_directory_addr::get_if_exists() == 0x0U);
}

void
vmcs_ut::test_vmcs_guest_pdpte2()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    this->expect_true(vmcs::guest_pdpte2::exists());

    vmcs::guest_pdpte2::set(1UL);
    this->expect_true(vmcs::guest_pdpte2::get() == 1UL);

    vmcs::guest_pdpte2::set_if_exists(0UL);
    this->expect_true(vmcs::guest_pdpte2::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_pdpte2_present()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte2::present::enable();
    this->expect_true(vmcs::guest_pdpte2::present::is_enabled());

    vmcs::guest_pdpte2::present::disable();
    this->expect_true(vmcs::guest_pdpte2::present::is_disabled());

    vmcs::guest_pdpte2::present::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte2::present::is_enabled_if_exists());

    vmcs::guest_pdpte2::present::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte2::present::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte2_reserved()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte2::reserved::set(6U);
    this->expect_true(vmcs::guest_pdpte2::reserved::get() == 6U);

    vmcs::guest_pdpte2::reserved::set_if_exists(0x8000000000000000U);
    this->expect_true(vmcs::guest_pdpte2::reserved::get_if_exists() == 0x8000000000000000U);
}

void
vmcs_ut::test_vmcs_guest_pdpte2_pwt()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte2::pwt::enable();
    this->expect_true(vmcs::guest_pdpte2::pwt::is_enabled());

    vmcs::guest_pdpte2::pwt::disable();
    this->expect_true(vmcs::guest_pdpte2::pwt::is_disabled());

    vmcs::guest_pdpte2::pwt::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte2::pwt::is_enabled_if_exists());

    vmcs::guest_pdpte2::pwt::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte2::pwt::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte2_pcd()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte2::pcd::enable();
    this->expect_true(vmcs::guest_pdpte2::pcd::is_enabled());

    vmcs::guest_pdpte2::pcd::disable();
    this->expect_true(vmcs::guest_pdpte2::pcd::is_disabled());

    vmcs::guest_pdpte2::pcd::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte2::pcd::is_enabled_if_exists());

    vmcs::guest_pdpte2::pcd::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte2::pcd::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte2_page_directory_addr()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;
    g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;

    vmcs::guest_pdpte2::page_directory_addr::set(0x100000000U);
    this->expect_true(vmcs::guest_pdpte2::page_directory_addr::get() == 0x100000000UL);

    vmcs::guest_pdpte2::page_directory_addr::set_if_exists(0x0U);
    this->expect_true(vmcs::guest_pdpte2::page_directory_addr::get_if_exists() == 0x0U);
}

void
vmcs_ut::test_vmcs_guest_pdpte3()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    this->expect_true(vmcs::guest_pdpte3::exists());

    vmcs::guest_pdpte3::set(1UL);
    this->expect_true(vmcs::guest_pdpte3::get() == 1UL);

    vmcs::guest_pdpte3::set_if_exists(0UL);
    this->expect_true(vmcs::guest_pdpte3::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_pdpte3_present()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte3::present::enable();
    this->expect_true(vmcs::guest_pdpte3::present::is_enabled());

    vmcs::guest_pdpte3::present::disable();
    this->expect_true(vmcs::guest_pdpte3::present::is_disabled());

    vmcs::guest_pdpte3::present::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte3::present::is_enabled_if_exists());

    vmcs::guest_pdpte3::present::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte3::present::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte3_reserved()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte3::reserved::set(6U);
    this->expect_true(vmcs::guest_pdpte3::reserved::get() == 6U);

    vmcs::guest_pdpte3::reserved::set_if_exists(0x8000000000000000U);
    this->expect_true(vmcs::guest_pdpte3::reserved::get_if_exists() == 0x8000000000000000U);
}

void
vmcs_ut::test_vmcs_guest_pdpte3_pwt()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte3::pwt::enable();
    this->expect_true(vmcs::guest_pdpte3::pwt::is_enabled());

    vmcs::guest_pdpte3::pwt::disable();
    this->expect_true(vmcs::guest_pdpte3::pwt::is_disabled());

    vmcs::guest_pdpte3::pwt::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte3::pwt::is_enabled_if_exists());

    vmcs::guest_pdpte3::pwt::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte3::pwt::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte3_pcd()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;

    vmcs::guest_pdpte3::pcd::enable();
    this->expect_true(vmcs::guest_pdpte3::pcd::is_enabled());

    vmcs::guest_pdpte3::pcd::disable();
    this->expect_true(vmcs::guest_pdpte3::pcd::is_disabled());

    vmcs::guest_pdpte3::pcd::enable_if_exists();
    this->expect_true(vmcs::guest_pdpte3::pcd::is_enabled_if_exists());

    vmcs::guest_pdpte3::pcd::disable_if_exists();
    this->expect_true(vmcs::guest_pdpte3::pcd::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pdpte3_page_directory_addr()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;
    g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;

    vmcs::guest_pdpte3::page_directory_addr::set(0x100000000U);
    this->expect_true(vmcs::guest_pdpte3::page_directory_addr::get() == 0x100000000UL);

    vmcs::guest_pdpte3::page_directory_addr::set_if_exists(0x0U);
    this->expect_true(vmcs::guest_pdpte3::page_directory_addr::get_if_exists() == 0x0U);
}

void
vmcs_ut::test_vmcs_guest_ia32_bndcfgs()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::mask << 32;
    this->expect_true(vmcs::guest_ia32_bndcfgs::exists());

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] &= ~(ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::mask << 32);
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= ia32_vmx_true_exit_ctls::clear_ia32_bndcfgs::mask << 32;
    this->expect_true(vmcs::guest_ia32_bndcfgs::exists());

    vmcs::guest_ia32_bndcfgs::set(1UL);
    this->expect_true(vmcs::guest_ia32_bndcfgs::get() == 1UL);

    vmcs::guest_ia32_bndcfgs::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ia32_bndcfgs::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_bndcfgs_en()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::mask << 32;

    vmcs::guest_ia32_bndcfgs::en::enable();
    this->expect_true(vmcs::guest_ia32_bndcfgs::en::is_enabled());

    vmcs::guest_ia32_bndcfgs::en::disable();
    this->expect_true(vmcs::guest_ia32_bndcfgs::en::is_disabled());

    vmcs::guest_ia32_bndcfgs::en::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_bndcfgs::en::is_enabled_if_exists());

    vmcs::guest_ia32_bndcfgs::en::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_bndcfgs::en::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_bndcfgs_bndpreserve()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::mask << 32;

    vmcs::guest_ia32_bndcfgs::bndpreserve::enable();
    this->expect_true(vmcs::guest_ia32_bndcfgs::bndpreserve::is_enabled());

    vmcs::guest_ia32_bndcfgs::bndpreserve::disable();
    this->expect_true(vmcs::guest_ia32_bndcfgs::bndpreserve::is_disabled());

    vmcs::guest_ia32_bndcfgs::bndpreserve::enable_if_exists();
    this->expect_true(vmcs::guest_ia32_bndcfgs::bndpreserve::is_enabled_if_exists());

    vmcs::guest_ia32_bndcfgs::bndpreserve::disable_if_exists();
    this->expect_true(vmcs::guest_ia32_bndcfgs::bndpreserve::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_bndcfgs_reserved()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::mask << 32;

    vmcs::guest_ia32_bndcfgs::reserved::set(0xCUL);
    this->expect_true(vmcs::guest_ia32_bndcfgs::reserved::get() == 0xCUL);

    vmcs::guest_ia32_bndcfgs::reserved::set_if_exists(0U);
    this->expect_true(vmcs::guest_ia32_bndcfgs::reserved::get_if_exists() == 0U);
}

void
vmcs_ut::test_vmcs_guest_ia32_bndcfgs_base_addr_of_bnd_directory()
{
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] |= ia32_vmx_true_entry_ctls::load_ia32_bndcfgs::mask << 32;

    vmcs::guest_ia32_bndcfgs::base_addr_of_bnd_directory::set(0x100000UL);
    this->expect_true(vmcs::guest_ia32_bndcfgs::base_addr_of_bnd_directory::get() == 0x100000UL);

    vmcs::guest_ia32_bndcfgs::base_addr_of_bnd_directory::set_if_exists(0U);
    this->expect_true(vmcs::guest_ia32_bndcfgs::base_addr_of_bnd_directory::get_if_exists() == 0U);
}

void
vmcs_ut::test_vmcs_guest_physical_address()
{
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32;
    this->expect_true(vmcs::guest_physical_address::exists());

    g_vmcs_fields[vmcs::guest_physical_address::addr] = 0x1U;
    this->expect_true(vmcs::guest_physical_address::get() == 0x1U);

    g_vmcs_fields[vmcs::guest_physical_address::addr] = 0x2U;
    this->expect_true(vmcs::guest_physical_address::get_if_exists() == 0x2U);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = ~(msrs::ia32_vmx_procbased_ctls2::enable_ept::mask << 32);
    this->expect_false(vmcs::guest_physical_address::exists());
    this->expect_exception([&] { vmcs::guest_physical_address::get(); }, ""_ut_lee);
    this->expect_no_exception([&] { vmcs::guest_physical_address::get_if_exists(); });
}

void
vmcs_ut::test_vmcs_host_ia32_pat()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;
    this->expect_true(vmcs::host_ia32_pat::exists());

    vmcs::host_ia32_pat::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::get() == 1UL);

    vmcs::host_ia32_pat::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa0()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa0::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa0::get() == 1UL);

    vmcs::host_ia32_pat::pa0::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa0::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa0_memory_type()
{
    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    pa0::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa0::memory_type::get() == x64::memory_type::uncacheable);

    pa0::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa0::memory_type::get() == x64::memory_type::write_combining);

    pa0::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa0::memory_type::get() == x64::memory_type::write_through);

    pa0::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa0::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa0::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa0::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa0::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa0::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa0_reserved()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa0::reserved::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa0::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa0::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa0::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa1()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa1::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa1::get() == 1UL);

    vmcs::host_ia32_pat::pa1::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa1::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa1_memory_type()
{
    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    pa1::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa1::memory_type::get() == x64::memory_type::uncacheable);

    pa1::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa1::memory_type::get() == x64::memory_type::write_combining);

    pa1::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa1::memory_type::get() == x64::memory_type::write_through);

    pa1::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa1::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa1::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa1::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa1::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa1::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa1_reserved()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa1::reserved::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa1::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa1::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa1::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa2()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa2::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa2::get() == 1UL);

    vmcs::host_ia32_pat::pa2::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa2::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa2_memory_type()
{
    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    pa2::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa2::memory_type::get() == x64::memory_type::uncacheable);

    pa2::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa2::memory_type::get() == x64::memory_type::write_combining);

    pa2::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa2::memory_type::get() == x64::memory_type::write_through);

    pa2::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa2::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa2::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa2::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa2::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa2::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa2_reserved()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa2::reserved::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa2::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa2::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa2::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa3()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa3::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa3::get() == 1UL);

    vmcs::host_ia32_pat::pa3::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa3::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa3_memory_type()
{
    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    pa3::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa3::memory_type::get() == x64::memory_type::uncacheable);

    pa3::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa3::memory_type::get() == x64::memory_type::write_combining);

    pa3::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa3::memory_type::get() == x64::memory_type::write_through);

    pa3::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa3::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa3::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa3::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa3::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa3::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa3_reserved()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa3::reserved::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa3::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa3::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa3::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa4()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa4::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa4::get() == 1UL);

    vmcs::host_ia32_pat::pa4::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa4::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa4_memory_type()
{
    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    pa4::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa4::memory_type::get() == x64::memory_type::uncacheable);

    pa4::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa4::memory_type::get() == x64::memory_type::write_combining);

    pa4::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa4::memory_type::get() == x64::memory_type::write_through);

    pa4::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa4::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa4::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa4::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa4::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa4::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa4_reserved()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa4::reserved::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa4::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa4::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa4::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa5()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa5::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa5::get() == 1UL);

    vmcs::host_ia32_pat::pa5::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa5::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa5_memory_type()
{
    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    pa5::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa5::memory_type::get() == x64::memory_type::uncacheable);

    pa5::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa5::memory_type::get() == x64::memory_type::write_combining);

    pa5::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa5::memory_type::get() == x64::memory_type::write_through);

    pa5::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa5::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa5::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa5::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa5::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa5::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa5_reserved()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa5::reserved::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa5::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa5::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa5::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa6()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa6::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa6::get() == 1UL);

    vmcs::host_ia32_pat::pa6::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa6::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa6_memory_type()
{
    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    pa6::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa6::memory_type::get() == x64::memory_type::uncacheable);

    pa6::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa6::memory_type::get() == x64::memory_type::write_combining);

    pa6::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa6::memory_type::get() == x64::memory_type::write_through);

    pa6::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa6::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa6::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa6::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa6::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa6::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa6_reserved()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa6::reserved::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa6::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa6::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa6::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa7()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa7::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa7::get() == 1UL);

    vmcs::host_ia32_pat::pa7::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa7::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa7_memory_type()
{
    using namespace vmcs::host_ia32_pat;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    pa7::memory_type::set(x64::memory_type::uncacheable);
    this->expect_true(pa7::memory_type::get() == x64::memory_type::uncacheable);

    pa7::memory_type::set(x64::memory_type::write_combining);
    this->expect_true(pa7::memory_type::get() == x64::memory_type::write_combining);

    pa7::memory_type::set(x64::memory_type::write_through);
    this->expect_true(pa7::memory_type::get() == x64::memory_type::write_through);

    pa7::memory_type::set_if_exists(x64::memory_type::write_protected);
    this->expect_true(pa7::memory_type::get_if_exists() == x64::memory_type::write_protected);

    pa7::memory_type::set_if_exists(x64::memory_type::write_back);
    this->expect_true(pa7::memory_type::get_if_exists() == x64::memory_type::write_back);

    pa7::memory_type::set_if_exists(x64::memory_type::uncached);
    this->expect_true(pa7::memory_type::get_if_exists() == x64::memory_type::uncached);
}

void
vmcs_ut::test_vmcs_host_ia32_pat_pa7_reserved()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_pat::mask << 32;

    vmcs::host_ia32_pat::pa7::reserved::set(1UL);
    this->expect_true(vmcs::host_ia32_pat::pa7::reserved::get() == 1UL);

    vmcs::host_ia32_pat::pa7::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_pat::pa7::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_efer()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask << 32;
    this->expect_true(vmcs::host_ia32_efer::exists());

    vmcs::host_ia32_efer::set(1UL);
    this->expect_true(vmcs::host_ia32_efer::get() == 1UL);

    vmcs::host_ia32_efer::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_efer::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_efer_sce()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask << 32;

    vmcs::host_ia32_efer::sce::enable();
    this->expect_true(vmcs::host_ia32_efer::sce::is_enabled());

    vmcs::host_ia32_efer::sce::disable();
    this->expect_true(vmcs::host_ia32_efer::sce::is_disabled());

    vmcs::host_ia32_efer::sce::enable_if_exists();
    this->expect_true(vmcs::host_ia32_efer::sce::is_enabled_if_exists());

    vmcs::host_ia32_efer::sce::disable_if_exists();
    this->expect_true(vmcs::host_ia32_efer::sce::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_ia32_efer_lme()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask << 32;

    vmcs::host_ia32_efer::lme::enable();
    this->expect_true(vmcs::host_ia32_efer::lme::is_enabled());

    vmcs::host_ia32_efer::lme::disable();
    this->expect_true(vmcs::host_ia32_efer::lme::is_disabled());

    vmcs::host_ia32_efer::lme::enable_if_exists();
    this->expect_true(vmcs::host_ia32_efer::lme::is_enabled_if_exists());

    vmcs::host_ia32_efer::lme::disable_if_exists();
    this->expect_true(vmcs::host_ia32_efer::lme::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_ia32_efer_lma()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask << 32;

    vmcs::host_ia32_efer::lma::enable();
    this->expect_true(vmcs::host_ia32_efer::lma::is_enabled());

    vmcs::host_ia32_efer::lma::disable();
    this->expect_true(vmcs::host_ia32_efer::lma::is_disabled());

    vmcs::host_ia32_efer::lma::enable_if_exists();
    this->expect_true(vmcs::host_ia32_efer::lma::is_enabled_if_exists());

    vmcs::host_ia32_efer::lma::disable_if_exists();
    this->expect_true(vmcs::host_ia32_efer::lma::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_ia32_efer_nxe()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask << 32;

    vmcs::host_ia32_efer::nxe::enable();
    this->expect_true(vmcs::host_ia32_efer::nxe::is_enabled());

    vmcs::host_ia32_efer::nxe::disable();
    this->expect_true(vmcs::host_ia32_efer::nxe::is_disabled());

    vmcs::host_ia32_efer::nxe::enable_if_exists();
    this->expect_true(vmcs::host_ia32_efer::nxe::is_enabled_if_exists());

    vmcs::host_ia32_efer::nxe::disable_if_exists();
    this->expect_true(vmcs::host_ia32_efer::nxe::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_ia32_efer_reserved()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_efer::mask << 32;

    vmcs::host_ia32_efer::reserved::set(0xEU);
    this->expect_true(vmcs::host_ia32_efer::reserved::get() == 0xEU);

    vmcs::host_ia32_efer::reserved::set_if_exists(0x0U);
    this->expect_true(vmcs::host_ia32_efer::reserved::get_if_exists() == 0x0U);
}

void
vmcs_ut::test_vmcs_host_ia32_perf_global_ctrl()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask << 32;
    this->expect_true(vmcs::host_ia32_perf_global_ctrl::exists());

    vmcs::host_ia32_perf_global_ctrl::set(1UL);
    this->expect_true(vmcs::host_ia32_perf_global_ctrl::get() == 1UL);

    vmcs::host_ia32_perf_global_ctrl::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_perf_global_ctrl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_perf_global_ctrl_reserved()
{
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] |= msrs::ia32_vmx_true_exit_ctls::load_ia32_perf_global_ctrl::mask << 32;
    this->expect_true(vmcs::host_ia32_perf_global_ctrl::exists());

    vmcs::host_ia32_perf_global_ctrl::reserved::set(0xCUL);
    this->expect_true(vmcs::host_ia32_perf_global_ctrl::reserved::get() == 0xCUL);

    vmcs::host_ia32_perf_global_ctrl::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_perf_global_ctrl::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags()
{
    this->expect_true(vmcs::guest_rflags::exists());

    vmcs::guest_rflags::set(100UL);
    this->expect_true(vmcs::guest_rflags::get() == 100UL);

    vmcs::guest_rflags::set_if_exists(0UL);
    this->expect_true(vmcs::guest_rflags::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_carry_flag()
{
    vmcs::guest_rflags::carry_flag::enable();
    this->expect_true(vmcs::guest_rflags::carry_flag::is_enabled());

    vmcs::guest_rflags::carry_flag::disable();
    this->expect_true(vmcs::guest_rflags::carry_flag::is_disabled());

    vmcs::guest_rflags::carry_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::carry_flag::is_enabled_if_exists());

    vmcs::guest_rflags::carry_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::carry_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_parity_flag()
{
    vmcs::guest_rflags::parity_flag::enable();
    this->expect_true(vmcs::guest_rflags::parity_flag::is_enabled());

    vmcs::guest_rflags::parity_flag::disable();
    this->expect_true(vmcs::guest_rflags::parity_flag::is_disabled());

    vmcs::guest_rflags::parity_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::parity_flag::is_enabled_if_exists());

    vmcs::guest_rflags::parity_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::parity_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_auxiliary_carry_flag()
{
    vmcs::guest_rflags::auxiliary_carry_flag::enable();
    this->expect_true(vmcs::guest_rflags::auxiliary_carry_flag::is_enabled());

    vmcs::guest_rflags::auxiliary_carry_flag::disable();
    this->expect_true(vmcs::guest_rflags::auxiliary_carry_flag::is_disabled());

    vmcs::guest_rflags::auxiliary_carry_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::auxiliary_carry_flag::is_enabled_if_exists());

    vmcs::guest_rflags::auxiliary_carry_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::auxiliary_carry_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_zero_flag()
{
    vmcs::guest_rflags::zero_flag::enable();
    this->expect_true(vmcs::guest_rflags::zero_flag::is_enabled());

    vmcs::guest_rflags::zero_flag::disable();
    this->expect_true(vmcs::guest_rflags::zero_flag::is_disabled());

    vmcs::guest_rflags::zero_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::zero_flag::is_enabled_if_exists());

    vmcs::guest_rflags::zero_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::zero_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_sign_flag()
{
    vmcs::guest_rflags::sign_flag::enable();
    this->expect_true(vmcs::guest_rflags::sign_flag::is_enabled());

    vmcs::guest_rflags::sign_flag::disable();
    this->expect_true(vmcs::guest_rflags::sign_flag::is_disabled());

    vmcs::guest_rflags::sign_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::sign_flag::is_enabled_if_exists());

    vmcs::guest_rflags::sign_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::sign_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_trap_flag()
{
    vmcs::guest_rflags::trap_flag::enable();
    this->expect_true(vmcs::guest_rflags::trap_flag::is_enabled());

    vmcs::guest_rflags::trap_flag::disable();
    this->expect_true(vmcs::guest_rflags::trap_flag::is_disabled());

    vmcs::guest_rflags::trap_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::trap_flag::is_enabled_if_exists());

    vmcs::guest_rflags::trap_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::trap_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_interrupt_enable_flag()
{
    vmcs::guest_rflags::interrupt_enable_flag::enable();
    this->expect_true(vmcs::guest_rflags::interrupt_enable_flag::is_enabled());

    vmcs::guest_rflags::interrupt_enable_flag::disable();
    this->expect_true(vmcs::guest_rflags::interrupt_enable_flag::is_disabled());

    vmcs::guest_rflags::interrupt_enable_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::interrupt_enable_flag::is_enabled_if_exists());

    vmcs::guest_rflags::interrupt_enable_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::interrupt_enable_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_direction_flag()
{
    vmcs::guest_rflags::direction_flag::enable();
    this->expect_true(vmcs::guest_rflags::direction_flag::is_enabled());

    vmcs::guest_rflags::direction_flag::disable();
    this->expect_true(vmcs::guest_rflags::direction_flag::is_disabled());

    vmcs::guest_rflags::direction_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::direction_flag::is_enabled_if_exists());

    vmcs::guest_rflags::direction_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::direction_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_overflow_flag()
{
    vmcs::guest_rflags::overflow_flag::enable();
    this->expect_true(vmcs::guest_rflags::overflow_flag::is_enabled());

    vmcs::guest_rflags::overflow_flag::disable();
    this->expect_true(vmcs::guest_rflags::overflow_flag::is_disabled());

    vmcs::guest_rflags::overflow_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::overflow_flag::is_enabled_if_exists());

    vmcs::guest_rflags::overflow_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::overflow_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_privilege_level()
{
    vmcs::guest_rflags::privilege_level::set(1UL);
    this->expect_true(vmcs::guest_rflags::privilege_level::get() == 1UL);

    vmcs::guest_rflags::privilege_level::set(2UL);
    this->expect_true(vmcs::guest_rflags::privilege_level::get() == 2UL);

    vmcs::guest_rflags::privilege_level::set_if_exists(3UL);
    this->expect_true(vmcs::guest_rflags::privilege_level::get_if_exists() == 3UL);

    vmcs::guest_rflags::privilege_level::set_if_exists(0UL);
    this->expect_true(vmcs::guest_rflags::privilege_level::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_nested_task()
{
    vmcs::guest_rflags::nested_task::enable();
    this->expect_true(vmcs::guest_rflags::nested_task::is_enabled());

    vmcs::guest_rflags::nested_task::disable();
    this->expect_true(vmcs::guest_rflags::nested_task::is_disabled());

    vmcs::guest_rflags::nested_task::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::nested_task::is_enabled_if_exists());

    vmcs::guest_rflags::nested_task::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::nested_task::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_resume_flag()
{
    vmcs::guest_rflags::resume_flag::enable();
    this->expect_true(vmcs::guest_rflags::resume_flag::is_enabled());

    vmcs::guest_rflags::resume_flag::disable();
    this->expect_true(vmcs::guest_rflags::resume_flag::is_disabled());

    vmcs::guest_rflags::resume_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::resume_flag::is_enabled_if_exists());

    vmcs::guest_rflags::resume_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::resume_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_virtual_8086_mode()
{
    vmcs::guest_rflags::virtual_8086_mode::enable();
    this->expect_true(vmcs::guest_rflags::virtual_8086_mode::is_enabled());

    vmcs::guest_rflags::virtual_8086_mode::disable();
    this->expect_true(vmcs::guest_rflags::virtual_8086_mode::is_disabled());

    vmcs::guest_rflags::virtual_8086_mode::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::virtual_8086_mode::is_enabled_if_exists());

    vmcs::guest_rflags::virtual_8086_mode::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::virtual_8086_mode::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_alignment_check_access_control()
{
    vmcs::guest_rflags::alignment_check_access_control::enable();
    this->expect_true(vmcs::guest_rflags::alignment_check_access_control::is_enabled());

    vmcs::guest_rflags::alignment_check_access_control::disable();
    this->expect_true(vmcs::guest_rflags::alignment_check_access_control::is_disabled());

    vmcs::guest_rflags::alignment_check_access_control::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::alignment_check_access_control::is_enabled_if_exists());

    vmcs::guest_rflags::alignment_check_access_control::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::alignment_check_access_control::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_virtual_interupt_flag()
{
    vmcs::guest_rflags::virtual_interrupt_flag::enable();
    this->expect_true(vmcs::guest_rflags::virtual_interrupt_flag::is_enabled());

    vmcs::guest_rflags::virtual_interrupt_flag::disable();
    this->expect_true(vmcs::guest_rflags::virtual_interrupt_flag::is_disabled());

    vmcs::guest_rflags::virtual_interrupt_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::virtual_interrupt_flag::is_enabled_if_exists());

    vmcs::guest_rflags::virtual_interrupt_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::virtual_interrupt_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_virtual_interupt_pending()
{
    vmcs::guest_rflags::virtual_interrupt_pending::enable();
    this->expect_true(vmcs::guest_rflags::virtual_interrupt_pending::is_enabled());

    vmcs::guest_rflags::virtual_interrupt_pending::disable();
    this->expect_true(vmcs::guest_rflags::virtual_interrupt_pending::is_disabled());

    vmcs::guest_rflags::virtual_interrupt_pending::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::virtual_interrupt_pending::is_enabled_if_exists());

    vmcs::guest_rflags::virtual_interrupt_pending::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::virtual_interrupt_pending::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_id_flag()
{
    vmcs::guest_rflags::id_flag::enable();
    this->expect_true(vmcs::guest_rflags::id_flag::is_enabled());

    vmcs::guest_rflags::id_flag::disable();
    this->expect_true(vmcs::guest_rflags::id_flag::is_disabled());

    vmcs::guest_rflags::id_flag::enable_if_exists();
    this->expect_true(vmcs::guest_rflags::id_flag::is_enabled_if_exists());

    vmcs::guest_rflags::id_flag::disable_if_exists();
    this->expect_true(vmcs::guest_rflags::id_flag::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_rflags_reserved()
{
    vmcs::guest_rflags::reserved::set(0x100000000UL);
    this->expect_true(vmcs::guest_rflags::reserved::get() == 0x100000000UL);

    vmcs::guest_rflags::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_rflags::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_always_disabled()
{
    vmcs::guest_rflags::always_disabled::set(0x100000000UL);
    this->expect_true(vmcs::guest_rflags::always_disabled::get() == 0x100000000UL);

    vmcs::guest_rflags::always_disabled::set_if_exists(0UL);
    this->expect_true(vmcs::guest_rflags::always_disabled::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rflags_always_enabled()
{
    vmcs::guest_rflags::always_enabled::set(2UL);
    this->expect_true(vmcs::guest_rflags::always_enabled::get() == 2UL);

    vmcs::guest_rflags::always_enabled::set_if_exists(0UL);
    this->expect_true(vmcs::guest_rflags::always_enabled::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_pending_debug_exceptions()
{
    this->expect_true(vmcs::guest_pending_debug_exceptions::exists());

    vmcs::guest_pending_debug_exceptions::set(1UL);
    this->expect_true(vmcs::guest_pending_debug_exceptions::get() == 1UL);

    vmcs::guest_pending_debug_exceptions::set_if_exists(0UL);
    this->expect_true(vmcs::guest_pending_debug_exceptions::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_pending_debug_exceptions_b0()
{
    vmcs::guest_pending_debug_exceptions::b0::enable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b0::is_enabled());

    vmcs::guest_pending_debug_exceptions::b0::disable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b0::is_disabled());

    vmcs::guest_pending_debug_exceptions::b0::enable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b0::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::b0::disable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b0::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pending_debug_exceptions_b1()
{
    vmcs::guest_pending_debug_exceptions::b1::enable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b1::is_enabled());

    vmcs::guest_pending_debug_exceptions::b1::disable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b1::is_disabled());

    vmcs::guest_pending_debug_exceptions::b1::enable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b1::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::b1::disable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b1::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pending_debug_exceptions_b2()
{
    vmcs::guest_pending_debug_exceptions::b2::enable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b2::is_enabled());

    vmcs::guest_pending_debug_exceptions::b2::disable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b2::is_disabled());

    vmcs::guest_pending_debug_exceptions::b2::enable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b2::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::b2::disable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b2::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pending_debug_exceptions_b3()
{
    vmcs::guest_pending_debug_exceptions::b3::enable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b3::is_enabled());

    vmcs::guest_pending_debug_exceptions::b3::disable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b3::is_disabled());

    vmcs::guest_pending_debug_exceptions::b3::enable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b3::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::b3::disable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::b3::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pending_debug_exceptions_reserved()
{
    vmcs::guest_pending_debug_exceptions::set(0x10UL);
    this->expect_true(vmcs::guest_pending_debug_exceptions::get() == 0x10UL);

    vmcs::guest_pending_debug_exceptions::set_if_exists(0x0UL);
    this->expect_true(vmcs::guest_pending_debug_exceptions::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_guest_pending_debug_exceptions_enabled_breakpoint()
{
    vmcs::guest_pending_debug_exceptions::enabled_breakpoint::enable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::enabled_breakpoint::is_enabled());

    vmcs::guest_pending_debug_exceptions::enabled_breakpoint::disable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::enabled_breakpoint::is_disabled());

    vmcs::guest_pending_debug_exceptions::enabled_breakpoint::enable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::enabled_breakpoint::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::enabled_breakpoint::disable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::enabled_breakpoint::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pending_debug_exceptions_bs()
{
    vmcs::guest_pending_debug_exceptions::bs::enable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::bs::is_enabled());

    vmcs::guest_pending_debug_exceptions::bs::disable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::bs::is_disabled());

    vmcs::guest_pending_debug_exceptions::bs::enable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::bs::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::bs::disable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::bs::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_pending_debug_exceptions_rtm()
{
    vmcs::guest_pending_debug_exceptions::rtm::enable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::rtm::is_enabled());

    vmcs::guest_pending_debug_exceptions::rtm::disable();
    this->expect_true(vmcs::guest_pending_debug_exceptions::rtm::is_disabled());

    vmcs::guest_pending_debug_exceptions::rtm::enable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::rtm::is_enabled_if_exists());

    vmcs::guest_pending_debug_exceptions::rtm::disable_if_exists();
    this->expect_true(vmcs::guest_pending_debug_exceptions::rtm::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_ia32_sysenter_esp()
{
    this->expect_true(vmcs::guest_ia32_sysenter_esp::exists());

    vmcs::guest_ia32_sysenter_esp::set_if_exists(0x0U);
    this->expect_true(vmcs::guest_ia32_sysenter_esp::get_if_exists() == 0U);

    vmcs::guest_ia32_sysenter_esp::set(0xFFFFFFFFU);
    this->expect_true(vmcs::guest_ia32_sysenter_esp::get() == 0xFFFFFFFFU);
}

void
vmcs_ut::test_vmcs_guest_ia32_sysenter_eip()
{
    this->expect_true(vmcs::guest_ia32_sysenter_eip::exists());

    vmcs::guest_ia32_sysenter_eip::set_if_exists(0x0U);
    this->expect_true(vmcs::guest_ia32_sysenter_eip::get_if_exists() == 0U);

    vmcs::guest_ia32_sysenter_eip::set(0xFFFFFFFFU);
    this->expect_true(vmcs::guest_ia32_sysenter_esp::get() == 0xFFFFFFFFU);
}

void
vmcs_ut::test_vmcs_guest_cr0()
{
    this->expect_true(vmcs::guest_cr0::exists());

    vmcs::guest_cr0::set_if_exists(0x0U);
    this->expect_true(vmcs::guest_cr0::get_if_exists() == 0U);

    vmcs::guest_cr0::set(0xFFFFFFFFU);
    this->expect_true(vmcs::guest_cr0::get() == 0xFFFFFFFFU);

    vmcs::guest_cr0::dump();
}

void
vmcs_ut::test_vmcs_guest_cr0_protection_enable()
{
    vmcs::guest_cr0::protection_enable::enable();
    this->expect_true(vmcs::guest_cr0::protection_enable::is_enabled());

    vmcs::guest_cr0::protection_enable::disable();
    this->expect_true(vmcs::guest_cr0::protection_enable::is_disabled());

    vmcs::guest_cr0::protection_enable::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::protection_enable::is_enabled_if_exists());

    vmcs::guest_cr0::protection_enable::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::protection_enable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr0_monitor_coprocessor()
{
    vmcs::guest_cr0::monitor_coprocessor::enable();
    this->expect_true(vmcs::guest_cr0::monitor_coprocessor::is_enabled());

    vmcs::guest_cr0::monitor_coprocessor::disable();
    this->expect_true(vmcs::guest_cr0::monitor_coprocessor::is_disabled());

    vmcs::guest_cr0::monitor_coprocessor::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::monitor_coprocessor::is_enabled_if_exists());

    vmcs::guest_cr0::monitor_coprocessor::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::monitor_coprocessor::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr0_emulation()
{
    vmcs::guest_cr0::emulation::enable();
    this->expect_true(vmcs::guest_cr0::emulation::is_enabled());

    vmcs::guest_cr0::emulation::disable();
    this->expect_true(vmcs::guest_cr0::emulation::is_disabled());

    vmcs::guest_cr0::emulation::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::emulation::is_enabled_if_exists());

    vmcs::guest_cr0::emulation::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::emulation::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr0_task_switched()
{
    vmcs::guest_cr0::task_switched::enable();
    this->expect_true(vmcs::guest_cr0::task_switched::is_enabled());

    vmcs::guest_cr0::task_switched::disable();
    this->expect_true(vmcs::guest_cr0::task_switched::is_disabled());

    vmcs::guest_cr0::task_switched::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::task_switched::is_enabled_if_exists());

    vmcs::guest_cr0::task_switched::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::protection_enable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr0_extension_type()
{
    vmcs::guest_cr0::extension_type::enable();
    this->expect_true(vmcs::guest_cr0::extension_type::is_enabled());

    vmcs::guest_cr0::extension_type::disable();
    this->expect_true(vmcs::guest_cr0::extension_type::is_disabled());

    vmcs::guest_cr0::extension_type::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::extension_type::is_enabled_if_exists());

    vmcs::guest_cr0::extension_type::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::extension_type::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr0_numeric_error()
{
    vmcs::guest_cr0::numeric_error::enable();
    this->expect_true(vmcs::guest_cr0::numeric_error::is_enabled());

    vmcs::guest_cr0::numeric_error::disable();
    this->expect_true(vmcs::guest_cr0::numeric_error::is_disabled());

    vmcs::guest_cr0::numeric_error::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::numeric_error::is_enabled_if_exists());

    vmcs::guest_cr0::numeric_error::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::numeric_error::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr0_write_protect()
{
    vmcs::guest_cr0::write_protect::enable();
    this->expect_true(vmcs::guest_cr0::write_protect::is_enabled());

    vmcs::guest_cr0::write_protect::disable();
    this->expect_true(vmcs::guest_cr0::write_protect::is_disabled());

    vmcs::guest_cr0::write_protect::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::write_protect::is_enabled_if_exists());

    vmcs::guest_cr0::write_protect::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::write_protect::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr0_alignment_mask()
{
    vmcs::guest_cr0::alignment_mask::enable();
    this->expect_true(vmcs::guest_cr0::alignment_mask::is_enabled());

    vmcs::guest_cr0::alignment_mask::disable();
    this->expect_true(vmcs::guest_cr0::alignment_mask::is_disabled());

    vmcs::guest_cr0::alignment_mask::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::alignment_mask::is_enabled_if_exists());

    vmcs::guest_cr0::alignment_mask::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::alignment_mask::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr0_not_write_through()
{
    vmcs::guest_cr0::not_write_through::enable();
    this->expect_true(vmcs::guest_cr0::not_write_through::is_enabled());

    vmcs::guest_cr0::not_write_through::disable();
    this->expect_true(vmcs::guest_cr0::not_write_through::is_disabled());

    vmcs::guest_cr0::not_write_through::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::not_write_through::is_enabled_if_exists());

    vmcs::guest_cr0::not_write_through::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::not_write_through::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr0_cache_disable()
{
    vmcs::guest_cr0::cache_disable::enable();
    this->expect_true(vmcs::guest_cr0::cache_disable::is_enabled());

    vmcs::guest_cr0::cache_disable::disable();
    this->expect_true(vmcs::guest_cr0::cache_disable::is_disabled());

    vmcs::guest_cr0::cache_disable::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::cache_disable::is_enabled_if_exists());

    vmcs::guest_cr0::cache_disable::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::cache_disable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr0_paging()
{
    vmcs::guest_cr0::paging::enable();
    this->expect_true(vmcs::guest_cr0::paging::is_enabled());

    vmcs::guest_cr0::paging::disable();
    this->expect_true(vmcs::guest_cr0::paging::is_disabled());

    vmcs::guest_cr0::paging::enable_if_exists();
    this->expect_true(vmcs::guest_cr0::paging::is_enabled_if_exists());

    vmcs::guest_cr0::paging::disable_if_exists();
    this->expect_true(vmcs::guest_cr0::paging::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr3()
{
    this->expect_true(vmcs::guest_cr3::exists());

    vmcs::guest_cr3::set(100UL);
    this->expect_true(vmcs::guest_cr3::get() == 100UL);

    vmcs::guest_cr3::set_if_exists(200UL);
    this->expect_true(vmcs::guest_cr3::get_if_exists() == 200UL);
}

void
vmcs_ut::test_vmcs_guest_cr4()
{
    this->expect_true(vmcs::guest_cr4::exists());

    vmcs::guest_cr4::set_if_exists(0x1U);
    this->expect_true(vmcs::guest_cr4::get_if_exists() == 0x1U);

    vmcs::guest_cr4::set(0xFFFFFFFFU);
    this->expect_true(vmcs::guest_cr4::get() == 0xFFFFFFFFU);

    vmcs::guest_cr4::dump();
}

void
vmcs_ut::test_vmcs_guest_cr4_v8086_mode_extensions()
{
    vmcs::guest_cr4::v8086_mode_extensions::enable();
    this->expect_true(vmcs::guest_cr4::v8086_mode_extensions::is_enabled());

    vmcs::guest_cr4::v8086_mode_extensions::disable();
    this->expect_true(vmcs::guest_cr4::v8086_mode_extensions::is_disabled());

    vmcs::guest_cr4::v8086_mode_extensions::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::v8086_mode_extensions::is_enabled_if_exists());

    vmcs::guest_cr4::v8086_mode_extensions::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::v8086_mode_extensions::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_protected_mode_virtual_interrupts()
{
    vmcs::guest_cr4::protected_mode_virtual_interrupts::enable();
    this->expect_true(vmcs::guest_cr4::protected_mode_virtual_interrupts::is_enabled());

    vmcs::guest_cr4::protected_mode_virtual_interrupts::disable();
    this->expect_true(vmcs::guest_cr4::protected_mode_virtual_interrupts::is_disabled());

    vmcs::guest_cr4::protected_mode_virtual_interrupts::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::protected_mode_virtual_interrupts::is_enabled_if_exists());

    vmcs::guest_cr4::protected_mode_virtual_interrupts::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::protected_mode_virtual_interrupts::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_time_stamp_disable()
{
    vmcs::guest_cr4::time_stamp_disable::enable();
    this->expect_true(vmcs::guest_cr4::time_stamp_disable::is_enabled());

    vmcs::guest_cr4::time_stamp_disable::disable();
    this->expect_true(vmcs::guest_cr4::time_stamp_disable::is_disabled());

    vmcs::guest_cr4::time_stamp_disable::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::time_stamp_disable::is_enabled_if_exists());

    vmcs::guest_cr4::time_stamp_disable::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::time_stamp_disable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_debugging_extensions()
{
    vmcs::guest_cr4::debugging_extensions::enable();
    this->expect_true(vmcs::guest_cr4::debugging_extensions::is_enabled());

    vmcs::guest_cr4::debugging_extensions::disable();
    this->expect_true(vmcs::guest_cr4::debugging_extensions::is_disabled());

    vmcs::guest_cr4::debugging_extensions::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::debugging_extensions::is_enabled_if_exists());

    vmcs::guest_cr4::debugging_extensions::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::debugging_extensions::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_page_size_extensions()
{
    vmcs::guest_cr4::page_size_extensions::enable();
    this->expect_true(vmcs::guest_cr4::page_size_extensions::is_enabled());

    vmcs::guest_cr4::page_size_extensions::disable();
    this->expect_true(vmcs::guest_cr4::page_size_extensions::is_disabled());

    vmcs::guest_cr4::page_size_extensions::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::page_size_extensions::is_enabled_if_exists());

    vmcs::guest_cr4::page_size_extensions::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::page_size_extensions::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_physical_address_extensions()
{
    vmcs::guest_cr4::physical_address_extensions::enable();
    this->expect_true(vmcs::guest_cr4::physical_address_extensions::is_enabled());

    vmcs::guest_cr4::physical_address_extensions::disable();
    this->expect_true(vmcs::guest_cr4::physical_address_extensions::is_disabled());

    vmcs::guest_cr4::physical_address_extensions::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::physical_address_extensions::is_enabled_if_exists());

    vmcs::guest_cr4::physical_address_extensions::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::physical_address_extensions::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_machine_check_enable()
{
    vmcs::guest_cr4::machine_check_enable::enable();
    this->expect_true(vmcs::guest_cr4::machine_check_enable::is_enabled());

    vmcs::guest_cr4::machine_check_enable::disable();
    this->expect_true(vmcs::guest_cr4::machine_check_enable::is_disabled());

    vmcs::guest_cr4::machine_check_enable::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::machine_check_enable::is_enabled_if_exists());

    vmcs::guest_cr4::machine_check_enable::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::machine_check_enable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_page_global_enable()
{
    vmcs::guest_cr4::page_global_enable::enable();
    this->expect_true(vmcs::guest_cr4::page_global_enable::is_enabled());

    vmcs::guest_cr4::page_global_enable::disable();
    this->expect_true(vmcs::guest_cr4::page_global_enable::is_disabled());

    vmcs::guest_cr4::page_global_enable::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::page_global_enable::is_enabled_if_exists());

    vmcs::guest_cr4::page_global_enable::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::page_global_enable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_performance_monitor_counter_enable()
{
    vmcs::guest_cr4::performance_monitor_counter_enable::enable();
    this->expect_true(vmcs::guest_cr4::performance_monitor_counter_enable::is_enabled());

    vmcs::guest_cr4::performance_monitor_counter_enable::disable();
    this->expect_true(vmcs::guest_cr4::performance_monitor_counter_enable::is_disabled());

    vmcs::guest_cr4::performance_monitor_counter_enable::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::performance_monitor_counter_enable::is_enabled_if_exists());

    vmcs::guest_cr4::performance_monitor_counter_enable::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::performance_monitor_counter_enable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_osfxsr()
{
    vmcs::guest_cr4::osfxsr::enable();
    this->expect_true(vmcs::guest_cr4::osfxsr::is_enabled());

    vmcs::guest_cr4::osfxsr::disable();
    this->expect_true(vmcs::guest_cr4::osfxsr::is_disabled());

    vmcs::guest_cr4::osfxsr::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::osfxsr::is_enabled_if_exists());

    vmcs::guest_cr4::osfxsr::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::osfxsr::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_osxmmexcpt()
{
    vmcs::guest_cr4::osxmmexcpt::enable();
    this->expect_true(vmcs::guest_cr4::osxmmexcpt::is_enabled());

    vmcs::guest_cr4::osxmmexcpt::disable();
    this->expect_true(vmcs::guest_cr4::osxmmexcpt::is_disabled());

    vmcs::guest_cr4::osxmmexcpt::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::osxmmexcpt::is_enabled_if_exists());

    vmcs::guest_cr4::osxmmexcpt::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::osxmmexcpt::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_vmx_enable_bit()
{
    vmcs::guest_cr4::vmx_enable_bit::enable();
    this->expect_true(vmcs::guest_cr4::vmx_enable_bit::is_enabled());

    vmcs::guest_cr4::vmx_enable_bit::disable();
    this->expect_true(vmcs::guest_cr4::vmx_enable_bit::is_disabled());

    vmcs::guest_cr4::vmx_enable_bit::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::vmx_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::vmx_enable_bit::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::vmx_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_smx_enable_bit()
{
    vmcs::guest_cr4::smx_enable_bit::enable();
    this->expect_true(vmcs::guest_cr4::smx_enable_bit::is_enabled());

    vmcs::guest_cr4::smx_enable_bit::disable();
    this->expect_true(vmcs::guest_cr4::smx_enable_bit::is_disabled());

    vmcs::guest_cr4::smx_enable_bit::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::smx_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::smx_enable_bit::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::smx_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_fsgsbase_enable_bit()
{
    vmcs::guest_cr4::fsgsbase_enable_bit::enable();
    this->expect_true(vmcs::guest_cr4::fsgsbase_enable_bit::is_enabled());

    vmcs::guest_cr4::fsgsbase_enable_bit::disable();
    this->expect_true(vmcs::guest_cr4::fsgsbase_enable_bit::is_disabled());

    vmcs::guest_cr4::fsgsbase_enable_bit::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::fsgsbase_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::fsgsbase_enable_bit::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::fsgsbase_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_pcid_enable_bit()
{
    vmcs::guest_cr4::pcid_enable_bit::enable();
    this->expect_true(vmcs::guest_cr4::pcid_enable_bit::is_enabled());

    vmcs::guest_cr4::pcid_enable_bit::disable();
    this->expect_true(vmcs::guest_cr4::pcid_enable_bit::is_disabled());

    vmcs::guest_cr4::pcid_enable_bit::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::pcid_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::pcid_enable_bit::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::pcid_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_osxsave()
{
    vmcs::guest_cr4::osxsave::enable();
    this->expect_true(vmcs::guest_cr4::osxsave::is_enabled());

    vmcs::guest_cr4::osxsave::disable();
    this->expect_true(vmcs::guest_cr4::osxsave::is_disabled());

    vmcs::guest_cr4::osxsave::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::osxsave::is_enabled_if_exists());

    vmcs::guest_cr4::osxsave::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::osxsave::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_smep_enable_bit()
{
    vmcs::guest_cr4::smep_enable_bit::enable();
    this->expect_true(vmcs::guest_cr4::smep_enable_bit::is_enabled());

    vmcs::guest_cr4::smep_enable_bit::disable();
    this->expect_true(vmcs::guest_cr4::smep_enable_bit::is_disabled());

    vmcs::guest_cr4::smep_enable_bit::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::smep_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::smep_enable_bit::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::smep_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_smap_enable_bit()
{
    vmcs::guest_cr4::smap_enable_bit::enable();
    this->expect_true(vmcs::guest_cr4::smap_enable_bit::is_enabled());

    vmcs::guest_cr4::smap_enable_bit::disable();
    this->expect_true(vmcs::guest_cr4::smap_enable_bit::is_disabled());

    vmcs::guest_cr4::smap_enable_bit::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::smap_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::smap_enable_bit::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::smap_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_cr4_protection_key_enable_bit()
{
    vmcs::guest_cr4::protection_key_enable_bit::enable();
    this->expect_true(vmcs::guest_cr4::protection_key_enable_bit::is_enabled());

    vmcs::guest_cr4::protection_key_enable_bit::disable();
    this->expect_true(vmcs::guest_cr4::protection_key_enable_bit::is_disabled());

    vmcs::guest_cr4::protection_key_enable_bit::enable_if_exists();
    this->expect_true(vmcs::guest_cr4::protection_key_enable_bit::is_enabled_if_exists());

    vmcs::guest_cr4::protection_key_enable_bit::disable_if_exists();
    this->expect_true(vmcs::guest_cr4::protection_key_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_guest_es_base()
{
    this->expect_true(vmcs::guest_es_base::exists());

    vmcs::guest_es_base::set(1UL);
    this->expect_true(vmcs::guest_es_base::get() == 1UL);

    vmcs::guest_es_base::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_base()
{
    this->expect_true(vmcs::guest_cs_base::exists());

    vmcs::guest_cs_base::set(1UL);
    this->expect_true(vmcs::guest_cs_base::get() == 1UL);

    vmcs::guest_cs_base::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_base()
{
    this->expect_true(vmcs::guest_ss_base::exists());

    vmcs::guest_ss_base::set(1UL);
    this->expect_true(vmcs::guest_ss_base::get() == 1UL);

    vmcs::guest_ss_base::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_base()
{
    this->expect_true(vmcs::guest_ds_base::exists());

    vmcs::guest_ds_base::set(1UL);
    this->expect_true(vmcs::guest_ds_base::get() == 1UL);

    vmcs::guest_ds_base::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_base()
{
    this->expect_true(vmcs::guest_fs_base::exists());

    vmcs::guest_fs_base::set(1UL);
    this->expect_true(vmcs::guest_fs_base::get() == 1UL);

    vmcs::guest_fs_base::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_base()
{
    this->expect_true(vmcs::guest_gs_base::exists());

    vmcs::guest_gs_base::set(1UL);
    this->expect_true(vmcs::guest_gs_base::get() == 1UL);

    vmcs::guest_gs_base::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_base()
{
    this->expect_true(vmcs::guest_ldtr_base::exists());

    vmcs::guest_ldtr_base::set(1UL);
    this->expect_true(vmcs::guest_ldtr_base::get() == 1UL);

    vmcs::guest_ldtr_base::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_base()
{
    this->expect_true(vmcs::guest_tr_base::exists());

    vmcs::guest_tr_base::set(1UL);
    this->expect_true(vmcs::guest_tr_base::get() == 1UL);

    vmcs::guest_tr_base::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gdtr_base()
{
    this->expect_true(vmcs::guest_gdtr_base::exists());

    vmcs::guest_gdtr_base::set(1UL);
    this->expect_true(vmcs::guest_gdtr_base::get() == 1UL);

    vmcs::guest_gdtr_base::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gdtr_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_idtr_base()
{
    this->expect_true(vmcs::guest_idtr_base::exists());

    vmcs::guest_idtr_base::set(1UL);
    this->expect_true(vmcs::guest_idtr_base::get() == 1UL);

    vmcs::guest_idtr_base::set_if_exists(0UL);
    this->expect_true(vmcs::guest_idtr_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_dr7()
{
    this->expect_true(vmcs::guest_dr7::exists());

    vmcs::guest_dr7::set(1UL);
    this->expect_true(vmcs::guest_dr7::get() == 1UL);

    vmcs::guest_dr7::set_if_exists(0UL);
    this->expect_true(vmcs::guest_dr7::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rsp()
{
    this->expect_true(vmcs::guest_rsp::exists());

    vmcs::guest_rsp::set(1UL);
    this->expect_true(vmcs::guest_rsp::get() == 1UL);

    vmcs::guest_rsp::set_if_exists(0UL);
    this->expect_true(vmcs::guest_rsp::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_rip()
{
    this->expect_true(vmcs::guest_rip::exists());

    vmcs::guest_rip::set(1UL);
    this->expect_true(vmcs::guest_rip::get() == 1UL);

    vmcs::guest_rip::set_if_exists(0UL);
    this->expect_true(vmcs::guest_rip::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_cr0()
{
    this->expect_true(vmcs::host_cr0::exists());

    vmcs::host_cr0::set_if_exists(0x2U);
    this->expect_true(vmcs::host_cr0::get_if_exists() == 0x2U);

    vmcs::host_cr0::set(0xFFFFFFFFU);
    this->expect_true(vmcs::host_cr0::get() == 0xFFFFFFFFU);

    vmcs::host_cr0::dump();
}

void
vmcs_ut::test_vmcs_host_cr0_protection_enable()
{
    vmcs::host_cr0::protection_enable::enable();
    this->expect_true(vmcs::host_cr0::protection_enable::is_enabled());

    vmcs::host_cr0::protection_enable::disable();
    this->expect_true(vmcs::host_cr0::protection_enable::is_disabled());

    vmcs::host_cr0::protection_enable::enable_if_exists();
    this->expect_true(vmcs::host_cr0::protection_enable::is_enabled_if_exists());

    vmcs::host_cr0::protection_enable::disable_if_exists();
    this->expect_true(vmcs::host_cr0::protection_enable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr0_monitor_coprocessor()
{
    vmcs::host_cr0::monitor_coprocessor::enable();
    this->expect_true(vmcs::host_cr0::monitor_coprocessor::is_enabled());

    vmcs::host_cr0::monitor_coprocessor::disable();
    this->expect_true(vmcs::host_cr0::monitor_coprocessor::is_disabled());

    vmcs::host_cr0::monitor_coprocessor::enable_if_exists();
    this->expect_true(vmcs::host_cr0::monitor_coprocessor::is_enabled_if_exists());

    vmcs::host_cr0::monitor_coprocessor::disable_if_exists();
    this->expect_true(vmcs::host_cr0::monitor_coprocessor::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr0_emulation()
{
    vmcs::host_cr0::emulation::enable();
    this->expect_true(vmcs::host_cr0::emulation::is_enabled());

    vmcs::host_cr0::emulation::disable();
    this->expect_true(vmcs::host_cr0::emulation::is_disabled());

    vmcs::host_cr0::emulation::enable_if_exists();
    this->expect_true(vmcs::host_cr0::emulation::is_enabled_if_exists());

    vmcs::host_cr0::emulation::disable_if_exists();
    this->expect_true(vmcs::host_cr0::emulation::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr0_task_switched()
{
    vmcs::host_cr0::task_switched::enable();
    this->expect_true(vmcs::host_cr0::task_switched::is_enabled());

    vmcs::host_cr0::task_switched::disable();
    this->expect_true(vmcs::host_cr0::task_switched::is_disabled());

    vmcs::host_cr0::task_switched::enable_if_exists();
    this->expect_true(vmcs::host_cr0::task_switched::is_enabled_if_exists());

    vmcs::host_cr0::task_switched::disable_if_exists();
    this->expect_true(vmcs::host_cr0::task_switched::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr0_extension_type()
{
    vmcs::host_cr0::extension_type::enable();
    this->expect_true(vmcs::host_cr0::extension_type::is_enabled());

    vmcs::host_cr0::extension_type::disable();
    this->expect_true(vmcs::host_cr0::extension_type::is_disabled());

    vmcs::host_cr0::extension_type::enable_if_exists();
    this->expect_true(vmcs::host_cr0::extension_type::is_enabled_if_exists());

    vmcs::host_cr0::extension_type::disable_if_exists();
    this->expect_true(vmcs::host_cr0::extension_type::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr0_numeric_error()
{
    vmcs::host_cr0::numeric_error::enable();
    this->expect_true(vmcs::host_cr0::numeric_error::is_enabled());

    vmcs::host_cr0::numeric_error::disable();
    this->expect_true(vmcs::host_cr0::numeric_error::is_disabled());

    vmcs::host_cr0::numeric_error::enable_if_exists();
    this->expect_true(vmcs::host_cr0::numeric_error::is_enabled_if_exists());

    vmcs::host_cr0::numeric_error::disable_if_exists();
    this->expect_true(vmcs::host_cr0::numeric_error::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr0_write_protect()
{
    vmcs::host_cr0::write_protect::enable();
    this->expect_true(vmcs::host_cr0::write_protect::is_enabled());

    vmcs::host_cr0::write_protect::disable();
    this->expect_true(vmcs::host_cr0::write_protect::is_disabled());

    vmcs::host_cr0::write_protect::enable_if_exists();
    this->expect_true(vmcs::host_cr0::write_protect::is_enabled_if_exists());

    vmcs::host_cr0::write_protect::disable_if_exists();
    this->expect_true(vmcs::host_cr0::write_protect::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr0_alignment_mask()
{
    vmcs::host_cr0::alignment_mask::enable();
    this->expect_true(vmcs::host_cr0::alignment_mask::is_enabled());

    vmcs::host_cr0::alignment_mask::disable();
    this->expect_true(vmcs::host_cr0::alignment_mask::is_disabled());

    vmcs::host_cr0::alignment_mask::enable_if_exists();
    this->expect_true(vmcs::host_cr0::alignment_mask::is_enabled_if_exists());

    vmcs::host_cr0::alignment_mask::disable_if_exists();
    this->expect_true(vmcs::host_cr0::alignment_mask::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr0_not_write_through()
{
    vmcs::host_cr0::not_write_through::enable();
    this->expect_true(vmcs::host_cr0::not_write_through::is_enabled());

    vmcs::host_cr0::not_write_through::disable();
    this->expect_true(vmcs::host_cr0::not_write_through::is_disabled());

    vmcs::host_cr0::not_write_through::enable_if_exists();
    this->expect_true(vmcs::host_cr0::not_write_through::is_enabled_if_exists());

    vmcs::host_cr0::not_write_through::disable_if_exists();
    this->expect_true(vmcs::host_cr0::not_write_through::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr0_cache_disable()
{
    vmcs::host_cr0::cache_disable::enable();
    this->expect_true(vmcs::host_cr0::cache_disable::is_enabled());

    vmcs::host_cr0::cache_disable::disable();
    this->expect_true(vmcs::host_cr0::cache_disable::is_disabled());

    vmcs::host_cr0::cache_disable::enable_if_exists();
    this->expect_true(vmcs::host_cr0::cache_disable::is_enabled_if_exists());

    vmcs::host_cr0::cache_disable::disable_if_exists();
    this->expect_true(vmcs::host_cr0::cache_disable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr0_paging()
{
    vmcs::host_cr0::paging::enable();
    this->expect_true(vmcs::host_cr0::paging::is_enabled());

    vmcs::host_cr0::paging::disable();
    this->expect_true(vmcs::host_cr0::paging::is_disabled());

    vmcs::host_cr0::paging::enable_if_exists();
    this->expect_true(vmcs::host_cr0::paging::is_enabled_if_exists());

    vmcs::host_cr0::paging::disable_if_exists();
    this->expect_true(vmcs::host_cr0::paging::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr3()
{
    this->expect_true(vmcs::host_cr3::exists());

    vmcs::host_cr3::set_if_exists(0x2U);
    this->expect_true(vmcs::host_cr3::get_if_exists() == 0x2U);

    vmcs::host_cr3::set(0xFFFFFFFFU);
    this->expect_true(vmcs::host_cr3::get() == 0xFFFFFFFFU);
}

void
vmcs_ut::test_vmcs_host_cr4()
{
    this->expect_true(vmcs::host_cr4::exists());

    vmcs::host_cr4::set_if_exists(0x2U);
    this->expect_true(vmcs::host_cr4::get_if_exists() == 0x2U);

    vmcs::host_cr4::set(0xFFFFFFFFU);
    this->expect_true(vmcs::host_cr4::get() == 0xFFFFFFFFU);

    vmcs::host_cr4::dump();
}

void
vmcs_ut::test_vmcs_host_cr4_v8086_mode_extensions()
{
    vmcs::host_cr4::v8086_mode_extensions::enable();
    this->expect_true(vmcs::host_cr4::v8086_mode_extensions::is_enabled());

    vmcs::host_cr4::v8086_mode_extensions::disable();
    this->expect_true(vmcs::host_cr4::v8086_mode_extensions::is_disabled());

    vmcs::host_cr4::v8086_mode_extensions::enable_if_exists();
    this->expect_true(vmcs::host_cr4::v8086_mode_extensions::is_enabled_if_exists());

    vmcs::host_cr4::v8086_mode_extensions::disable_if_exists();
    this->expect_true(vmcs::host_cr4::v8086_mode_extensions::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_protected_mode_virtual_interrupts()
{
    vmcs::host_cr4::protected_mode_virtual_interrupts::enable();
    this->expect_true(vmcs::host_cr4::protected_mode_virtual_interrupts::is_enabled());

    vmcs::host_cr4::protected_mode_virtual_interrupts::disable();
    this->expect_true(vmcs::host_cr4::protected_mode_virtual_interrupts::is_disabled());

    vmcs::host_cr4::protected_mode_virtual_interrupts::enable_if_exists();
    this->expect_true(vmcs::host_cr4::protected_mode_virtual_interrupts::is_enabled_if_exists());

    vmcs::host_cr4::protected_mode_virtual_interrupts::disable_if_exists();
    this->expect_true(vmcs::host_cr4::protected_mode_virtual_interrupts::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_time_stamp_disable()
{
    vmcs::host_cr4::time_stamp_disable::enable();
    this->expect_true(vmcs::host_cr4::time_stamp_disable::is_enabled());

    vmcs::host_cr4::time_stamp_disable::disable();
    this->expect_true(vmcs::host_cr4::time_stamp_disable::is_disabled());

    vmcs::host_cr4::time_stamp_disable::enable_if_exists();
    this->expect_true(vmcs::host_cr4::time_stamp_disable::is_enabled_if_exists());

    vmcs::host_cr4::time_stamp_disable::disable_if_exists();
    this->expect_true(vmcs::host_cr4::time_stamp_disable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_debugging_extensions()
{
    vmcs::host_cr4::debugging_extensions::enable();
    this->expect_true(vmcs::host_cr4::debugging_extensions::is_enabled());

    vmcs::host_cr4::debugging_extensions::disable();
    this->expect_true(vmcs::host_cr4::debugging_extensions::is_disabled());

    vmcs::host_cr4::debugging_extensions::enable_if_exists();
    this->expect_true(vmcs::host_cr4::debugging_extensions::is_enabled_if_exists());

    vmcs::host_cr4::debugging_extensions::disable_if_exists();
    this->expect_true(vmcs::host_cr4::debugging_extensions::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_page_size_extensions()
{
    vmcs::host_cr4::page_size_extensions::enable();
    this->expect_true(vmcs::host_cr4::page_size_extensions::is_enabled());

    vmcs::host_cr4::page_size_extensions::disable();
    this->expect_true(vmcs::host_cr4::page_size_extensions::is_disabled());

    vmcs::host_cr4::page_size_extensions::enable_if_exists();
    this->expect_true(vmcs::host_cr4::page_size_extensions::is_enabled_if_exists());

    vmcs::host_cr4::page_size_extensions::disable_if_exists();
    this->expect_true(vmcs::host_cr4::page_size_extensions::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_physical_address_extensions()
{
    vmcs::host_cr4::physical_address_extensions::enable();
    this->expect_true(vmcs::host_cr4::physical_address_extensions::is_enabled());

    vmcs::host_cr4::physical_address_extensions::disable();
    this->expect_true(vmcs::host_cr4::physical_address_extensions::is_disabled());

    vmcs::host_cr4::physical_address_extensions::enable_if_exists();
    this->expect_true(vmcs::host_cr4::physical_address_extensions::is_enabled_if_exists());

    vmcs::host_cr4::physical_address_extensions::disable_if_exists();
    this->expect_true(vmcs::host_cr4::physical_address_extensions::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_machine_check_enable()
{
    vmcs::host_cr4::machine_check_enable::enable();
    this->expect_true(vmcs::host_cr4::machine_check_enable::is_enabled());

    vmcs::host_cr4::machine_check_enable::disable();
    this->expect_true(vmcs::host_cr4::machine_check_enable::is_disabled());

    vmcs::host_cr4::machine_check_enable::enable_if_exists();
    this->expect_true(vmcs::host_cr4::machine_check_enable::is_enabled_if_exists());

    vmcs::host_cr4::machine_check_enable::disable_if_exists();
    this->expect_true(vmcs::host_cr4::machine_check_enable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_page_global_enable()
{
    vmcs::host_cr4::page_global_enable::enable();
    this->expect_true(vmcs::host_cr4::page_global_enable::is_enabled());

    vmcs::host_cr4::page_global_enable::disable();
    this->expect_true(vmcs::host_cr4::page_global_enable::is_disabled());

    vmcs::host_cr4::page_global_enable::enable_if_exists();
    this->expect_true(vmcs::host_cr4::page_global_enable::is_enabled_if_exists());

    vmcs::host_cr4::page_global_enable::disable_if_exists();
    this->expect_true(vmcs::host_cr4::page_global_enable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_performance_monitor_counter_enable()
{
    vmcs::host_cr4::performance_monitor_counter_enable::enable();
    this->expect_true(vmcs::host_cr4::performance_monitor_counter_enable::is_enabled());

    vmcs::host_cr4::performance_monitor_counter_enable::disable();
    this->expect_true(vmcs::host_cr4::performance_monitor_counter_enable::is_disabled());

    vmcs::host_cr4::performance_monitor_counter_enable::enable_if_exists();
    this->expect_true(vmcs::host_cr4::performance_monitor_counter_enable::is_enabled_if_exists());

    vmcs::host_cr4::performance_monitor_counter_enable::disable_if_exists();
    this->expect_true(vmcs::host_cr4::performance_monitor_counter_enable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_osfxsr()
{
    vmcs::host_cr4::osfxsr::enable();
    this->expect_true(vmcs::host_cr4::osfxsr::is_enabled());

    vmcs::host_cr4::osfxsr::disable();
    this->expect_true(vmcs::host_cr4::osfxsr::is_disabled());

    vmcs::host_cr4::osfxsr::enable_if_exists();
    this->expect_true(vmcs::host_cr4::osfxsr::is_enabled_if_exists());

    vmcs::host_cr4::osfxsr::disable_if_exists();
    this->expect_true(vmcs::host_cr4::osfxsr::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_osxmmexcpt()
{
    vmcs::host_cr4::osxmmexcpt::enable();
    this->expect_true(vmcs::host_cr4::osxmmexcpt::is_enabled());

    vmcs::host_cr4::osxmmexcpt::disable();
    this->expect_true(vmcs::host_cr4::osxmmexcpt::is_disabled());

    vmcs::host_cr4::osxmmexcpt::enable_if_exists();
    this->expect_true(vmcs::host_cr4::osxmmexcpt::is_enabled_if_exists());

    vmcs::host_cr4::osxmmexcpt::disable_if_exists();
    this->expect_true(vmcs::host_cr4::osxmmexcpt::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_vmx_enable_bit()
{
    vmcs::host_cr4::vmx_enable_bit::enable();
    this->expect_true(vmcs::host_cr4::vmx_enable_bit::is_enabled());

    vmcs::host_cr4::vmx_enable_bit::disable();
    this->expect_true(vmcs::host_cr4::vmx_enable_bit::is_disabled());

    vmcs::host_cr4::vmx_enable_bit::enable_if_exists();
    this->expect_true(vmcs::host_cr4::vmx_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::vmx_enable_bit::disable_if_exists();
    this->expect_true(vmcs::host_cr4::vmx_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_smx_enable_bit()
{
    vmcs::host_cr4::smx_enable_bit::enable();
    this->expect_true(vmcs::host_cr4::smx_enable_bit::is_enabled());

    vmcs::host_cr4::smx_enable_bit::disable();
    this->expect_true(vmcs::host_cr4::smx_enable_bit::is_disabled());

    vmcs::host_cr4::smx_enable_bit::enable_if_exists();
    this->expect_true(vmcs::host_cr4::smx_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::smx_enable_bit::disable_if_exists();
    this->expect_true(vmcs::host_cr4::smx_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_fsgsbase_enable_bit()
{
    vmcs::host_cr4::fsgsbase_enable_bit::enable();
    this->expect_true(vmcs::host_cr4::fsgsbase_enable_bit::is_enabled());

    vmcs::host_cr4::fsgsbase_enable_bit::disable();
    this->expect_true(vmcs::host_cr4::fsgsbase_enable_bit::is_disabled());

    vmcs::host_cr4::fsgsbase_enable_bit::enable_if_exists();
    this->expect_true(vmcs::host_cr4::fsgsbase_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::fsgsbase_enable_bit::disable_if_exists();
    this->expect_true(vmcs::host_cr4::fsgsbase_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_pcid_enable_bit()
{
    vmcs::host_cr4::pcid_enable_bit::enable();
    this->expect_true(vmcs::host_cr4::pcid_enable_bit::is_enabled());

    vmcs::host_cr4::pcid_enable_bit::disable();
    this->expect_true(vmcs::host_cr4::pcid_enable_bit::is_disabled());

    vmcs::host_cr4::pcid_enable_bit::enable_if_exists();
    this->expect_true(vmcs::host_cr4::pcid_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::pcid_enable_bit::disable_if_exists();
    this->expect_true(vmcs::host_cr4::pcid_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_osxsave()
{
    vmcs::host_cr4::osxsave::enable();
    this->expect_true(vmcs::host_cr4::osxsave::is_enabled());

    vmcs::host_cr4::osxsave::disable();
    this->expect_true(vmcs::host_cr4::osxsave::is_disabled());

    vmcs::host_cr4::osxsave::enable_if_exists();
    this->expect_true(vmcs::host_cr4::osxsave::is_enabled_if_exists());

    vmcs::host_cr4::osxsave::disable_if_exists();
    this->expect_true(vmcs::host_cr4::osxsave::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_smep_enable_bit()
{
    vmcs::host_cr4::smep_enable_bit::enable();
    this->expect_true(vmcs::host_cr4::smep_enable_bit::is_enabled());

    vmcs::host_cr4::smep_enable_bit::disable();
    this->expect_true(vmcs::host_cr4::smep_enable_bit::is_disabled());

    vmcs::host_cr4::smep_enable_bit::enable_if_exists();
    this->expect_true(vmcs::host_cr4::smep_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::smep_enable_bit::disable_if_exists();
    this->expect_true(vmcs::host_cr4::smep_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_smap_enable_bit()
{
    vmcs::host_cr4::smap_enable_bit::enable();
    this->expect_true(vmcs::host_cr4::smap_enable_bit::is_enabled());

    vmcs::host_cr4::smap_enable_bit::disable();
    this->expect_true(vmcs::host_cr4::smap_enable_bit::is_disabled());

    vmcs::host_cr4::smap_enable_bit::enable_if_exists();
    this->expect_true(vmcs::host_cr4::smap_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::smap_enable_bit::disable_if_exists();
    this->expect_true(vmcs::host_cr4::smap_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_cr4_protection_key_enable_bit()
{
    vmcs::host_cr4::protection_key_enable_bit::enable();
    this->expect_true(vmcs::host_cr4::protection_key_enable_bit::is_enabled());

    vmcs::host_cr4::protection_key_enable_bit::disable();
    this->expect_true(vmcs::host_cr4::protection_key_enable_bit::is_disabled());

    vmcs::host_cr4::protection_key_enable_bit::enable_if_exists();
    this->expect_true(vmcs::host_cr4::protection_key_enable_bit::is_enabled_if_exists());

    vmcs::host_cr4::protection_key_enable_bit::disable_if_exists();
    this->expect_true(vmcs::host_cr4::protection_key_enable_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_host_fs_base()
{
    this->expect_true(vmcs::host_fs_base::exists());

    vmcs::host_fs_base::set(1UL);
    this->expect_true(vmcs::host_fs_base::get() == 1UL);

    vmcs::host_fs_base::set_if_exists(0UL);
    this->expect_true(vmcs::host_fs_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_gs_base()
{
    this->expect_true(vmcs::host_gs_base::exists());

    vmcs::host_gs_base::set(1UL);
    this->expect_true(vmcs::host_gs_base::get() == 1UL);

    vmcs::host_gs_base::set_if_exists(0UL);
    this->expect_true(vmcs::host_gs_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_tr_base()
{
    this->expect_true(vmcs::host_tr_base::exists());

    vmcs::host_tr_base::set(1UL);
    this->expect_true(vmcs::host_tr_base::get() == 1UL);

    vmcs::host_tr_base::set_if_exists(0UL);
    this->expect_true(vmcs::host_tr_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_gdtr_base()
{
    this->expect_true(vmcs::host_gdtr_base::exists());

    vmcs::host_gdtr_base::set(1UL);
    this->expect_true(vmcs::host_gdtr_base::get() == 1UL);

    vmcs::host_gdtr_base::set_if_exists(0UL);
    this->expect_true(vmcs::host_gdtr_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_idtr_base()
{
    this->expect_true(vmcs::host_idtr_base::exists());

    vmcs::host_idtr_base::set(1UL);
    this->expect_true(vmcs::host_idtr_base::get() == 1UL);

    vmcs::host_idtr_base::set_if_exists(0UL);
    this->expect_true(vmcs::host_idtr_base::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_sysenter_esp()
{
    this->expect_true(vmcs::host_ia32_sysenter_esp::exists());

    vmcs::host_ia32_sysenter_esp::set(1UL);
    this->expect_true(vmcs::host_ia32_sysenter_esp::get() == 1UL);

    vmcs::host_ia32_sysenter_esp::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_sysenter_esp::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_ia32_sysenter_eip()
{
    this->expect_true(vmcs::host_ia32_sysenter_eip::exists());

    vmcs::host_ia32_sysenter_eip::set(1UL);
    this->expect_true(vmcs::host_ia32_sysenter_eip::get() == 1UL);

    vmcs::host_ia32_sysenter_eip::set_if_exists(0UL);
    this->expect_true(vmcs::host_ia32_sysenter_eip::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_rsp()
{
    this->expect_true(vmcs::host_rsp::exists());

    vmcs::host_rsp::set(1UL);
    this->expect_true(vmcs::host_rsp::get() == 1UL);

    vmcs::host_rsp::set_if_exists(0UL);
    this->expect_true(vmcs::host_rsp::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_host_rip()
{
    this->expect_true(vmcs::host_rip::exists());

    vmcs::host_rip::set(1UL);
    this->expect_true(vmcs::host_rip::get() == 1UL);

    vmcs::host_rip::set_if_exists(0UL);
    this->expect_true(vmcs::host_rip::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_limit()
{
    this->expect_true(vmcs::guest_es_limit::exists());

    vmcs::guest_es_limit::set(1UL);
    this->expect_true(vmcs::guest_es_limit::get() == 1UL);

    vmcs::guest_es_limit::set_if_exists(1UL);
    this->expect_true(vmcs::guest_es_limit::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_cs_limit()
{
    this->expect_true(vmcs::guest_cs_limit::exists());

    vmcs::guest_cs_limit::set(1UL);
    this->expect_true(vmcs::guest_cs_limit::get() == 1UL);

    vmcs::guest_cs_limit::set_if_exists(1UL);
    this->expect_true(vmcs::guest_cs_limit::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ss_limit()
{
    this->expect_true(vmcs::guest_ss_limit::exists());

    vmcs::guest_ss_limit::set(1UL);
    this->expect_true(vmcs::guest_ss_limit::get() == 1UL);

    vmcs::guest_ss_limit::set_if_exists(1UL);
    this->expect_true(vmcs::guest_ss_limit::get_if_exists() == 1UL);
}


void
vmcs_ut::test_vmcs_guest_ds_limit()
{
    this->expect_true(vmcs::guest_ds_limit::exists());

    vmcs::guest_ds_limit::set(1UL);
    this->expect_true(vmcs::guest_ds_limit::get() == 1UL);

    vmcs::guest_ds_limit::set_if_exists(1UL);
    this->expect_true(vmcs::guest_ds_limit::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_fs_limit()
{
    this->expect_true(vmcs::guest_fs_limit::exists());

    vmcs::guest_fs_limit::set(1UL);
    this->expect_true(vmcs::guest_fs_limit::get() == 1UL);

    vmcs::guest_fs_limit::set_if_exists(1UL);
    this->expect_true(vmcs::guest_fs_limit::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gs_limit()
{
    this->expect_true(vmcs::guest_gs_limit::exists());

    vmcs::guest_gs_limit::set(1UL);
    this->expect_true(vmcs::guest_gs_limit::get() == 1UL);

    vmcs::guest_gs_limit::set_if_exists(1UL);
    this->expect_true(vmcs::guest_gs_limit::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_limit()
{
    this->expect_true(vmcs::guest_ldtr_limit::exists());

    vmcs::guest_ldtr_limit::set(1UL);
    this->expect_true(vmcs::guest_ldtr_limit::get() == 1UL);

    vmcs::guest_ldtr_limit::set_if_exists(1UL);
    this->expect_true(vmcs::guest_ldtr_limit::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_tr_limit()
{
    this->expect_true(vmcs::guest_tr_limit::exists());

    vmcs::guest_tr_limit::set(1UL);
    this->expect_true(vmcs::guest_tr_limit::get() == 1UL);

    vmcs::guest_tr_limit::set_if_exists(1UL);
    this->expect_true(vmcs::guest_tr_limit::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_gdtr_limit()
{
    this->expect_true(vmcs::guest_gdtr_limit::exists());

    vmcs::guest_gdtr_limit::set(1UL);
    this->expect_true(vmcs::guest_gdtr_limit::get() == 1UL);

    vmcs::guest_gdtr_limit::set_if_exists(1UL);
    this->expect_true(vmcs::guest_gdtr_limit::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_idtr_limit()
{
    this->expect_true(vmcs::guest_idtr_limit::exists());

    vmcs::guest_idtr_limit::set(1UL);
    this->expect_true(vmcs::guest_idtr_limit::get() == 1UL);

    vmcs::guest_idtr_limit::set_if_exists(1UL);
    this->expect_true(vmcs::guest_idtr_limit::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights()
{
    vmcs::guest_es_access_rights::set(100UL);
    this->expect_true(vmcs::guest_es_access_rights::exists());
    this->expect_true(vmcs::guest_es_access_rights::get() == 100UL);

    vmcs::guest_es_access_rights::set_if_exists(2UL);
    this->expect_true(vmcs::guest_es_access_rights::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_type()
{
    vmcs::guest_es_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::type::get() == 1UL);

    vmcs::guest_es_access_rights::type::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_access_rights::type::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_s()
{
    vmcs::guest_es_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::s::get() == 1UL);

    vmcs::guest_es_access_rights::s::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_access_rights::s::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_dpl()
{
    vmcs::guest_es_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::dpl::get() == 1UL);

    vmcs::guest_es_access_rights::dpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_access_rights::dpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_present()
{
    vmcs::guest_es_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::present::get() == 1UL);

    vmcs::guest_es_access_rights::present::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_access_rights::present::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_avl()
{
    vmcs::guest_es_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::avl::get() == 1UL);

    vmcs::guest_es_access_rights::avl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_access_rights::avl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_l()
{
    vmcs::guest_es_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::l::get() == 1UL);

    vmcs::guest_es_access_rights::l::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_access_rights::l::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_db()
{
    vmcs::guest_es_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::db::get() == 1UL);

    vmcs::guest_es_access_rights::db::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_access_rights::db::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_granularity()
{
    vmcs::guest_es_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::granularity::get() == 1UL);

    vmcs::guest_es_access_rights::granularity::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_access_rights::granularity::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_reserved()
{
    vmcs::guest_es_access_rights::reserved::set(0x10F00U);
    this->expect_true(vmcs::guest_es_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_es_access_rights::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_access_rights::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_es_access_rights_unusable()
{
    vmcs::guest_es_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_es_access_rights::unusable::get() == 1UL);

    vmcs::guest_es_access_rights::unusable::set_if_exists(0UL);
    this->expect_true(vmcs::guest_es_access_rights::unusable::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights()
{
    vmcs::guest_cs_access_rights::set(100UL);
    this->expect_true(vmcs::guest_cs_access_rights::exists());
    this->expect_true(vmcs::guest_cs_access_rights::get() == 100UL);

    vmcs::guest_cs_access_rights::set_if_exists(2UL);
    this->expect_true(vmcs::guest_cs_access_rights::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_type()
{
    vmcs::guest_cs_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::type::get() == 1UL);

    vmcs::guest_cs_access_rights::type::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_access_rights::type::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_s()
{
    vmcs::guest_cs_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::s::get() == 1UL);

    vmcs::guest_cs_access_rights::s::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_access_rights::s::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_dpl()
{
    vmcs::guest_cs_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::dpl::get() == 1UL);

    vmcs::guest_cs_access_rights::dpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_access_rights::dpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_present()
{
    vmcs::guest_cs_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::present::get() == 1UL);

    vmcs::guest_cs_access_rights::present::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_access_rights::present::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_avl()
{
    vmcs::guest_cs_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::avl::get() == 1UL);

    vmcs::guest_cs_access_rights::avl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_access_rights::avl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_l()
{
    vmcs::guest_cs_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::l::get() == 1UL);

    vmcs::guest_cs_access_rights::l::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_access_rights::l::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_db()
{
    vmcs::guest_cs_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::db::get() == 1UL);

    vmcs::guest_cs_access_rights::db::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_access_rights::db::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_granularity()
{
    vmcs::guest_cs_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::granularity::get() == 1UL);

    vmcs::guest_cs_access_rights::granularity::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_access_rights::granularity::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_reserved()
{
    vmcs::guest_cs_access_rights::reserved::set(0x10F00U);
    this->expect_true(vmcs::guest_cs_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_cs_access_rights::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_access_rights::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_cs_access_rights_unusable()
{
    vmcs::guest_cs_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_cs_access_rights::unusable::get() == 1UL);

    vmcs::guest_cs_access_rights::unusable::set_if_exists(0UL);
    this->expect_true(vmcs::guest_cs_access_rights::unusable::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights()
{
    vmcs::guest_ss_access_rights::set(100UL);
    this->expect_true(vmcs::guest_ss_access_rights::exists());
    this->expect_true(vmcs::guest_ss_access_rights::get() == 100UL);

    vmcs::guest_ss_access_rights::set_if_exists(2UL);
    this->expect_true(vmcs::guest_ss_access_rights::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_type()
{
    vmcs::guest_ss_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::type::get() == 1UL);

    vmcs::guest_ss_access_rights::type::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_access_rights::type::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_s()
{
    vmcs::guest_ss_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::s::get() == 1UL);

    vmcs::guest_ss_access_rights::s::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_access_rights::s::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_dpl()
{
    vmcs::guest_ss_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::dpl::get() == 1UL);

    vmcs::guest_ss_access_rights::dpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_access_rights::dpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_present()
{
    vmcs::guest_ss_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::present::get() == 1UL);

    vmcs::guest_ss_access_rights::present::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_access_rights::present::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_avl()
{
    vmcs::guest_ss_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::avl::get() == 1UL);

    vmcs::guest_ss_access_rights::avl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_access_rights::avl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_l()
{
    vmcs::guest_ss_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::l::get() == 1UL);

    vmcs::guest_ss_access_rights::l::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_access_rights::l::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_db()
{
    vmcs::guest_ss_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::db::get() == 1UL);

    vmcs::guest_ss_access_rights::db::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_access_rights::db::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_granularity()
{
    vmcs::guest_ss_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::granularity::get() == 1UL);

    vmcs::guest_ss_access_rights::granularity::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_access_rights::granularity::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_reserved()
{
    vmcs::guest_ss_access_rights::reserved::set(0x10F00U);
    this->expect_true(vmcs::guest_ss_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_ss_access_rights::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_access_rights::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ss_access_rights_unusable()
{
    vmcs::guest_ss_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_ss_access_rights::unusable::get() == 1UL);

    vmcs::guest_ss_access_rights::unusable::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ss_access_rights::unusable::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights()
{
    vmcs::guest_ds_access_rights::set(100UL);
    this->expect_true(vmcs::guest_ds_access_rights::exists());
    this->expect_true(vmcs::guest_ds_access_rights::get() == 100UL);

    vmcs::guest_ds_access_rights::set_if_exists(2UL);
    this->expect_true(vmcs::guest_ds_access_rights::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_type()
{
    vmcs::guest_ds_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::type::get() == 1UL);

    vmcs::guest_ds_access_rights::type::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_access_rights::type::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_s()
{
    vmcs::guest_ds_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::s::get() == 1UL);

    vmcs::guest_ds_access_rights::s::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_access_rights::s::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_dpl()
{
    vmcs::guest_ds_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::dpl::get() == 1UL);

    vmcs::guest_ds_access_rights::dpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_access_rights::dpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_present()
{
    vmcs::guest_ds_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::present::get() == 1UL);

    vmcs::guest_ds_access_rights::present::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_access_rights::present::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_avl()
{
    vmcs::guest_ds_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::avl::get() == 1UL);

    vmcs::guest_ds_access_rights::avl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_access_rights::avl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_l()
{
    vmcs::guest_ds_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::l::get() == 1UL);

    vmcs::guest_ds_access_rights::l::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_access_rights::l::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_db()
{
    vmcs::guest_ds_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::db::get() == 1UL);

    vmcs::guest_ds_access_rights::db::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_access_rights::db::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_granularity()
{
    vmcs::guest_ds_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::granularity::get() == 1UL);

    vmcs::guest_ds_access_rights::granularity::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_access_rights::granularity::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_reserved()
{
    vmcs::guest_ds_access_rights::reserved::set(0x10F00U);
    this->expect_true(vmcs::guest_ds_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_ds_access_rights::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_access_rights::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ds_access_rights_unusable()
{
    vmcs::guest_ds_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_ds_access_rights::unusable::get() == 1UL);

    vmcs::guest_ds_access_rights::unusable::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ds_access_rights::unusable::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights()
{
    vmcs::guest_fs_access_rights::set(100UL);
    this->expect_true(vmcs::guest_fs_access_rights::exists());
    this->expect_true(vmcs::guest_fs_access_rights::get() == 100UL);

    vmcs::guest_fs_access_rights::set_if_exists(2UL);
    this->expect_true(vmcs::guest_fs_access_rights::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_type()
{
    vmcs::guest_fs_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::type::get() == 1UL);

    vmcs::guest_fs_access_rights::type::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_access_rights::type::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_s()
{
    vmcs::guest_fs_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::s::get() == 1UL);

    vmcs::guest_fs_access_rights::s::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_access_rights::s::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_dpl()
{
    vmcs::guest_fs_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::dpl::get() == 1UL);

    vmcs::guest_fs_access_rights::dpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_access_rights::dpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_present()
{
    vmcs::guest_fs_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::present::get() == 1UL);

    vmcs::guest_fs_access_rights::present::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_access_rights::present::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_avl()
{
    vmcs::guest_fs_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::avl::get() == 1UL);

    vmcs::guest_fs_access_rights::avl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_access_rights::avl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_l()
{
    vmcs::guest_fs_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::l::get() == 1UL);

    vmcs::guest_fs_access_rights::l::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_access_rights::l::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_db()
{
    vmcs::guest_fs_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::db::get() == 1UL);

    vmcs::guest_fs_access_rights::db::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_access_rights::db::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_granularity()
{
    vmcs::guest_fs_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::granularity::get() == 1UL);

    vmcs::guest_fs_access_rights::granularity::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_access_rights::granularity::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_reserved()
{
    vmcs::guest_fs_access_rights::reserved::set(0x10F00U);
    this->expect_true(vmcs::guest_fs_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_fs_access_rights::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_access_rights::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_fs_access_rights_unusable()
{
    vmcs::guest_fs_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_fs_access_rights::unusable::get() == 1UL);

    vmcs::guest_fs_access_rights::unusable::set_if_exists(0UL);
    this->expect_true(vmcs::guest_fs_access_rights::unusable::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights()
{
    vmcs::guest_gs_access_rights::set(100UL);
    this->expect_true(vmcs::guest_gs_access_rights::exists());
    this->expect_true(vmcs::guest_gs_access_rights::get() == 100UL);

    vmcs::guest_gs_access_rights::set_if_exists(2UL);
    this->expect_true(vmcs::guest_gs_access_rights::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_type()
{
    vmcs::guest_gs_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::type::get() == 1UL);

    vmcs::guest_gs_access_rights::type::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_access_rights::type::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_s()
{
    vmcs::guest_gs_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::s::get() == 1UL);

    vmcs::guest_gs_access_rights::s::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_access_rights::s::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_dpl()
{
    vmcs::guest_gs_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::dpl::get() == 1UL);

    vmcs::guest_gs_access_rights::dpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_access_rights::dpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_present()
{
    vmcs::guest_gs_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::present::get() == 1UL);

    vmcs::guest_gs_access_rights::present::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_access_rights::present::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_avl()
{
    vmcs::guest_gs_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::avl::get() == 1UL);

    vmcs::guest_gs_access_rights::avl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_access_rights::avl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_l()
{
    vmcs::guest_gs_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::l::get() == 1UL);

    vmcs::guest_gs_access_rights::l::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_access_rights::l::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_db()
{
    vmcs::guest_gs_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::db::get() == 1UL);

    vmcs::guest_gs_access_rights::db::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_access_rights::db::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_granularity()
{
    vmcs::guest_gs_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::granularity::get() == 1UL);

    vmcs::guest_gs_access_rights::granularity::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_access_rights::granularity::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_reserved()
{
    vmcs::guest_gs_access_rights::reserved::set(0x10F00U);
    this->expect_true(vmcs::guest_gs_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_gs_access_rights::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_access_rights::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_gs_access_rights_unusable()
{
    vmcs::guest_gs_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_gs_access_rights::unusable::get() == 1UL);

    vmcs::guest_gs_access_rights::unusable::set_if_exists(0UL);
    this->expect_true(vmcs::guest_gs_access_rights::unusable::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights()
{
    vmcs::guest_ldtr_access_rights::set(100UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::exists());
    this->expect_true(vmcs::guest_ldtr_access_rights::get() == 100UL);

    vmcs::guest_ldtr_access_rights::set_if_exists(2UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_type()
{
    vmcs::guest_ldtr_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::type::get() == 1UL);

    vmcs::guest_ldtr_access_rights::type::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::type::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_s()
{
    vmcs::guest_ldtr_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::s::get() == 1UL);

    vmcs::guest_ldtr_access_rights::s::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::s::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_dpl()
{
    vmcs::guest_ldtr_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::dpl::get() == 1UL);

    vmcs::guest_ldtr_access_rights::dpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::dpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_present()
{
    vmcs::guest_ldtr_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::present::get() == 1UL);

    vmcs::guest_ldtr_access_rights::present::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::present::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_avl()
{
    vmcs::guest_ldtr_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::avl::get() == 1UL);

    vmcs::guest_ldtr_access_rights::avl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::avl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_l()
{
    vmcs::guest_ldtr_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::l::get() == 1UL);

    vmcs::guest_ldtr_access_rights::l::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::l::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_db()
{
    vmcs::guest_ldtr_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::db::get() == 1UL);

    vmcs::guest_ldtr_access_rights::db::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::db::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_granularity()
{
    vmcs::guest_ldtr_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::granularity::get() == 1UL);

    vmcs::guest_ldtr_access_rights::granularity::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::granularity::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_reserved()
{
    vmcs::guest_ldtr_access_rights::reserved::set(0x10F00U);
    this->expect_true(vmcs::guest_ldtr_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_ldtr_access_rights::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_ldtr_access_rights_unusable()
{
    vmcs::guest_ldtr_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::unusable::get() == 1UL);

    vmcs::guest_ldtr_access_rights::unusable::set_if_exists(0UL);
    this->expect_true(vmcs::guest_ldtr_access_rights::unusable::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights()
{
    vmcs::guest_tr_access_rights::set(100UL);
    this->expect_true(vmcs::guest_tr_access_rights::exists());
    this->expect_true(vmcs::guest_tr_access_rights::get() == 100UL);

    vmcs::guest_tr_access_rights::set_if_exists(2UL);
    this->expect_true(vmcs::guest_tr_access_rights::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_type()
{
    vmcs::guest_tr_access_rights::type::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::type::get() == 1UL);

    vmcs::guest_tr_access_rights::type::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_access_rights::type::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_s()
{
    vmcs::guest_tr_access_rights::s::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::s::get() == 1UL);

    vmcs::guest_tr_access_rights::s::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_access_rights::s::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_dpl()
{
    vmcs::guest_tr_access_rights::dpl::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::dpl::get() == 1UL);

    vmcs::guest_tr_access_rights::dpl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_access_rights::dpl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_present()
{
    vmcs::guest_tr_access_rights::present::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::present::get() == 1UL);

    vmcs::guest_tr_access_rights::present::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_access_rights::present::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_avl()
{
    vmcs::guest_tr_access_rights::avl::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::avl::get() == 1UL);

    vmcs::guest_tr_access_rights::avl::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_access_rights::avl::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_l()
{
    vmcs::guest_tr_access_rights::l::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::l::get() == 1UL);

    vmcs::guest_tr_access_rights::l::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_access_rights::l::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_db()
{
    vmcs::guest_tr_access_rights::db::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::db::get() == 1UL);

    vmcs::guest_tr_access_rights::db::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_access_rights::db::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_granularity()
{
    vmcs::guest_tr_access_rights::granularity::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::granularity::get() == 1UL);

    vmcs::guest_tr_access_rights::granularity::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_access_rights::granularity::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_reserved()
{
    vmcs::guest_tr_access_rights::reserved::set(0x10F00U);
    this->expect_true(vmcs::guest_tr_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_tr_access_rights::reserved::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_access_rights::reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_tr_access_rights_unusable()
{
    vmcs::guest_tr_access_rights::unusable::set(1UL);
    this->expect_true(vmcs::guest_tr_access_rights::unusable::get() == 1UL);

    vmcs::guest_tr_access_rights::unusable::set_if_exists(0UL);
    this->expect_true(vmcs::guest_tr_access_rights::unusable::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_interruptibility_state()
{
    this->expect_true(vmcs::guest_interruptibility_state::exists());

    vmcs::guest_interruptibility_state::set(1UL);
    this->expect_true(vmcs::guest_interruptibility_state::get() == 1UL);

    vmcs::guest_interruptibility_state::set_if_exists(2UL);
    this->expect_true(vmcs::guest_interruptibility_state::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_guest_interruptibility_state_blocking_by_sti()
{
    using namespace vmcs::guest_interruptibility_state;

    blocking_by_sti::set(1UL);
    this->expect_true(blocking_by_sti::get() == 1UL);

    blocking_by_sti::set_if_exists(0UL);
    this->expect_true(blocking_by_sti::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_interruptibility_state_blocking_by_mov_ss()
{
    using namespace vmcs::guest_interruptibility_state;

    blocking_by_mov_ss::set(1UL);
    this->expect_true(blocking_by_mov_ss::get() == 1UL);

    blocking_by_mov_ss::set_if_exists(0UL);
    this->expect_true(blocking_by_mov_ss::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_interruptibility_state_blocking_by_smi()
{
    using namespace vmcs::guest_interruptibility_state;

    blocking_by_smi::set(1UL);
    this->expect_true(blocking_by_smi::get() == 1UL);

    blocking_by_smi::set_if_exists(0UL);
    this->expect_true(blocking_by_smi::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_interruptibility_state_blocking_by_nmi()
{
    using namespace vmcs::guest_interruptibility_state;

    blocking_by_nmi::set(1UL);
    this->expect_true(blocking_by_nmi::get() == 1UL);

    blocking_by_nmi::set_if_exists(0UL);
    this->expect_true(blocking_by_nmi::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_interruptibility_state_enclave_interruption()
{
    using namespace vmcs::guest_interruptibility_state;

    enclave_interruption::set(1UL);
    this->expect_true(enclave_interruption::get() == 1UL);

    enclave_interruption::set_if_exists(0UL);
    this->expect_true(enclave_interruption::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_interruptibility_state_reserved()
{
    using namespace vmcs::guest_interruptibility_state;

    reserved::set(1UL);
    this->expect_true(reserved::get() == 1UL);

    reserved::set_if_exists(0UL);
    this->expect_true(reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_guest_activity_state()
{
    this->expect_true(vmcs::guest_activity_state::exists());

    vmcs::guest_activity_state::set(vmcs::guest_activity_state::active);
    this->expect_true(vmcs::guest_activity_state::get() == 0U);

    vmcs::guest_activity_state::set(vmcs::guest_activity_state::hlt);
    this->expect_true(vmcs::guest_activity_state::get() == 1U);

    vmcs::guest_activity_state::set_if_exists(vmcs::guest_activity_state::shutdown);
    this->expect_true(vmcs::guest_activity_state::get_if_exists() == 2U);

    vmcs::guest_activity_state::set_if_exists(vmcs::guest_activity_state::wait_for_sipi);
    this->expect_true(vmcs::guest_activity_state::get_if_exists() == 3U);
}

void
vmcs_ut::test_vmcs_guest_smbase()
{
    this->expect_true(vmcs::guest_smbase::exists());

    vmcs::guest_smbase::set(1UL);
    this->expect_true(vmcs::guest_smbase::get() == 1UL);

    vmcs::guest_smbase::set_if_exists(2UL);
    this->expect_true(vmcs::guest_smbase::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_guest_ia32_sysenter_cs()
{
    this->expect_true(vmcs::guest_ia32_sysenter_cs::exists());

    vmcs::guest_ia32_sysenter_cs::set(1UL);
    this->expect_true(vmcs::guest_ia32_sysenter_cs::get() == 1UL);

    vmcs::guest_ia32_sysenter_cs::set_if_exists(2UL);
    this->expect_true(vmcs::guest_ia32_sysenter_cs::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_vmx_preemption_timer_value()
{
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::mask << 32;
    this->expect_true(vmcs::vmx_preemption_timer_value::exists());

    vmcs::vmx_preemption_timer_value::set(1UL);
    this->expect_true(vmcs::vmx_preemption_timer_value::get() == 1UL);

    vmcs::vmx_preemption_timer_value::set_if_exists(2UL);
    this->expect_true(vmcs::vmx_preemption_timer_value::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_host_ia32_sysenter_cs()
{
    this->expect_true(vmcs::host_ia32_sysenter_cs::exists());

    vmcs::host_ia32_sysenter_cs::set(42U);
    this->expect_true(vmcs::host_ia32_sysenter_cs::get() == 42U);

    vmcs::host_ia32_sysenter_cs::set_if_exists(0x1000U);
    this->expect_true(vmcs::host_ia32_sysenter_cs::get_if_exists() == 0x1000U);
}

void
vmcs_ut::test_vmcs_cr0_guest_host_mask()
{
    this->expect_true(vmcs::cr0_guest_host_mask::exists());

    vmcs::cr0_guest_host_mask::set(1UL);
    this->expect_true(vmcs::cr0_guest_host_mask::get() == 1UL);

    vmcs::cr0_guest_host_mask::set_if_exists(2UL);
    this->expect_true(vmcs::cr0_guest_host_mask::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_cr4_guest_host_mask()
{
    this->expect_true(vmcs::cr4_guest_host_mask::exists());

    vmcs::cr4_guest_host_mask::set(1UL);
    this->expect_true(vmcs::cr4_guest_host_mask::get() == 1UL);

    vmcs::cr4_guest_host_mask::set_if_exists(2UL);
    this->expect_true(vmcs::cr4_guest_host_mask::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_cr0_read_shadow()
{
    this->expect_true(vmcs::cr0_read_shadow::exists());

    vmcs::cr0_read_shadow::set(1UL);
    this->expect_true(vmcs::cr0_read_shadow::get() == 1UL);

    vmcs::cr0_read_shadow::set_if_exists(2UL);
    this->expect_true(vmcs::cr0_read_shadow::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_cr4_read_shadow()
{
    this->expect_true(vmcs::cr4_read_shadow::exists());

    vmcs::cr4_read_shadow::set(1UL);
    this->expect_true(vmcs::cr4_read_shadow::get() == 1UL);

    vmcs::cr4_read_shadow::set_if_exists(2UL);
    this->expect_true(vmcs::cr4_read_shadow::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_cr3_target_value_0()
{
    this->expect_true(vmcs::cr3_target_value_0::exists());

    vmcs::cr3_target_value_0::set(1UL);
    this->expect_true(vmcs::cr3_target_value_0::get() == 1UL);

    vmcs::cr3_target_value_0::set_if_exists(2UL);
    this->expect_true(vmcs::cr3_target_value_0::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_cr3_target_value_1()
{
    this->expect_true(vmcs::cr3_target_value_1::exists());

    vmcs::cr3_target_value_1::set(1UL);
    this->expect_true(vmcs::cr3_target_value_1::get() == 1UL);

    vmcs::cr3_target_value_1::set_if_exists(2UL);
    this->expect_true(vmcs::cr3_target_value_1::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_cr3_target_value_2()
{
    this->expect_true(vmcs::cr3_target_value_2::exists());

    vmcs::cr3_target_value_2::set(1UL);
    this->expect_true(vmcs::cr3_target_value_2::get() == 1UL);

    vmcs::cr3_target_value_2::set_if_exists(2UL);
    this->expect_true(vmcs::cr3_target_value_2::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_cr3_target_value_3()
{
    this->expect_true(vmcs::cr3_target_value_3::exists());

    vmcs::cr3_target_value_3::set(1UL);
    this->expect_true(vmcs::cr3_target_value_3::get() == 1UL);

    vmcs::cr3_target_value_3::set_if_exists(2UL);
    this->expect_true(vmcs::cr3_target_value_3::get_if_exists() == 2UL);
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
vmcs_ut::test_vmcs_vm_exit_controls_clear_ia32_bndcfgs()
{
    using namespace vmcs::vm_exit_controls::clear_ia32_bndcfgs;

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
vmcs_ut::test_vmcs_vm_entry_controls_load_ia32_bndcfgs()
{
    using namespace vmcs::vm_entry_controls::load_ia32_bndcfgs;

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

void
vmcs_ut::test_vmcs_ple_gap()
{
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask << 32;

    this->expect_true(vmcs::ple_gap::exists());

    vmcs::ple_gap::set(0x11UL);
    this->expect_true(vmcs::ple_gap::get() == 0x11UL);

    vmcs::ple_gap::set_if_exists(0xFFFUL);
    this->expect_true(vmcs::ple_gap::get_if_exists() == 0xFFFUL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0;
    this->expect_false(vmcs::ple_gap::exists());
    this->expect_exception([&] { vmcs::ple_gap::set(0x3U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::ple_gap::get(); }, ""_ut_lee);
    this->expect_no_exception([&] { vmcs::ple_gap::set_if_exists(0x3U); });
    this->expect_no_exception([&] { vmcs::ple_gap::get_if_exists(); });

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask << 32;
    this->expect_true(vmcs::ple_gap::get() == 0xFFFUL);
}

void
vmcs_ut::test_vmcs_ple_window()
{
    using namespace msrs::ia32_vmx_true_procbased_ctls;

    g_msrs[addr] = activate_secondary_controls::mask << 32;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask << 32;

    this->expect_true(vmcs::ple_window::exists());

    vmcs::ple_window::set(0x11UL);
    this->expect_true(vmcs::ple_window::get() == 0x11UL);

    vmcs::ple_window::set_if_exists(0xFFFUL);
    this->expect_true(vmcs::ple_window::get_if_exists() == 0xFFFUL);

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0;
    this->expect_false(vmcs::ple_window::exists());
    this->expect_exception([&] { vmcs::ple_window::set(0x3U); }, ""_ut_lee);
    this->expect_exception([&] { vmcs::ple_window::get(); }, ""_ut_lee);
    this->expect_no_exception([&] { vmcs::ple_window::set_if_exists(0x3U); });
    this->expect_no_exception([&] { vmcs::ple_window::get_if_exists(); });

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::pause_loop_exiting::mask << 32;
    this->expect_true(vmcs::ple_window::get() == 0xFFFUL);
}

void
vmcs_ut::test_vmcs_vm_instruction_error()
{
    this->expect_true(vmcs::vm_instruction_error::exists());

    for (auto && code : vm_instruction_error_codes)
    {
        g_vmcs_fields[vmcs::vm_instruction_error::addr] = code.first;
        this->expect_true(vmcs::vm_instruction_error::get() == code.first);
        this->expect_true(vmcs::vm_instruction_error::get_if_exists() == code.first);
        this->expect_true(vmcs::vm_instruction_error::description() == code.second);
        this->expect_true(vmcs::vm_instruction_error::description_if_exists() == code.second);
    }
}

void
vmcs_ut::test_vmcs_exit_reason()
{
    this->expect_true(vmcs::exit_reason::exists());

    g_vmcs_fields[vmcs::exit_reason::addr] = 1UL;
    this->expect_true(vmcs::exit_reason::get() == 1UL);

    g_vmcs_fields[vmcs::exit_reason::addr] = 2UL;
    this->expect_true(vmcs::exit_reason::get_if_exists() == 2UL);
}

void
vmcs_ut::test_vmcs_exit_reason_basic_exit_reason()
{
    using namespace vmcs::exit_reason;

    for (auto && reason : exit_reasons)
    {
        g_vmcs_fields[addr] = reason.first << basic_exit_reason::from;
        this->expect_true(basic_exit_reason::get() == reason.first);
        this->expect_true(basic_exit_reason::get_if_exists() == reason.first);
        this->expect_true(basic_exit_reason::description() == reason.second);
        this->expect_true(basic_exit_reason::description_if_exists() == reason.second);
    }
}

void
vmcs_ut::test_vmcs_exit_reason_reserved()
{
    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = reserved::mask;
    this->expect_true(reserved::get() == reserved::mask >> reserved::from);
    this->expect_true(reserved::get_if_exists() == reserved::mask >> reserved::from);
}

void
vmcs_ut::test_vmcs_exit_reason_vm_exit_incident_to_enclave_mode()
{
    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = 0UL;
    this->expect_true(vm_exit_incident_to_enclave_mode::is_disabled());
    this->expect_true(vm_exit_incident_to_enclave_mode::is_disabled_if_exists());

    g_vmcs_fields[addr] = vm_exit_incident_to_enclave_mode::mask;
    this->expect_true(vm_exit_incident_to_enclave_mode::is_enabled());
    this->expect_true(vm_exit_incident_to_enclave_mode::is_enabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_reason_pending_mtf_vm_exit()
{
    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = 0UL;
    this->expect_true(pending_mtf_vm_exit::is_disabled());
    this->expect_true(pending_mtf_vm_exit::is_disabled_if_exists());

    g_vmcs_fields[addr] = pending_mtf_vm_exit::mask;
    this->expect_true(pending_mtf_vm_exit::is_enabled());
    this->expect_true(pending_mtf_vm_exit::is_enabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_reason_vm_exit_from_vmx_root_operation()
{
    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = 0UL;
    this->expect_true(vm_exit_from_vmx_root_operation::is_disabled());
    this->expect_true(vm_exit_from_vmx_root_operation::is_disabled_if_exists());

    g_vmcs_fields[addr] = vm_exit_from_vmx_root_operation::mask;
    this->expect_true(vm_exit_from_vmx_root_operation::is_enabled());
    this->expect_true(vm_exit_from_vmx_root_operation::is_enabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_reason_vm_entry_failure()
{
    using namespace vmcs::exit_reason;

    g_vmcs_fields[addr] = 0UL;
    this->expect_true(vm_entry_failure::is_disabled());
    this->expect_true(vm_entry_failure::is_disabled_if_exists());

    g_vmcs_fields[addr] = vm_entry_failure::mask;
    this->expect_true(vm_entry_failure::is_enabled());
    this->expect_true(vm_entry_failure::is_enabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_interruption_information()
{
    this->expect_true(vmcs::vm_exit_interruption_information::exists());

    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 1UL;
    this->expect_true(vmcs::vm_exit_interruption_information::get() == 1UL);
    this->expect_true(vmcs::vm_exit_interruption_information::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_interruption_information_vector()
{
    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0xFFFUL;

    this->expect_true(vmcs::vm_exit_interruption_information::vector::get() == 0xFFUL);
    this->expect_true(vmcs::vm_exit_interruption_information::vector::get_if_exists() == 0xFFUL);
}

void
vmcs_ut::test_vmcs_vm_exit_interruption_information_interruption_type()
{
    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0xFFFUL;

    this->expect_true(vmcs::vm_exit_interruption_information::interruption_type::get() == 7UL);
    this->expect_true(vmcs::vm_exit_interruption_information::interruption_type::get_if_exists() == 7UL);
}

void
vmcs_ut::test_vmcs_vm_exit_interruption_information_error_code_valid()
{
    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0xFFFUL;

    this->expect_true(vmcs::vm_exit_interruption_information::error_code_valid::is_enabled());
    this->expect_true(vmcs::vm_exit_interruption_information::error_code_valid::is_enabled_if_exists());

    this->expect_false(vmcs::vm_exit_interruption_information::error_code_valid::is_disabled());
    this->expect_false(vmcs::vm_exit_interruption_information::error_code_valid::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_interruption_information_nmi_blocking_due_to_iret()
{
    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0x1000UL;

    this->expect_true(vmcs::vm_exit_interruption_information::nmi_unblocking_due_to_iret::is_enabled());
    this->expect_true(vmcs::vm_exit_interruption_information::nmi_unblocking_due_to_iret::is_enabled_if_exists());

    this->expect_false(vmcs::vm_exit_interruption_information::nmi_unblocking_due_to_iret::is_disabled());
    this->expect_false(vmcs::vm_exit_interruption_information::nmi_unblocking_due_to_iret::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_interruption_information_reserved()
{
    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0xEE000UL;

    this->expect_true(vmcs::vm_exit_interruption_information::reserved::get() == 0xEE000U);
    this->expect_true(vmcs::vm_exit_interruption_information::reserved::get_if_exists() == 0xEE000U);
}

void
vmcs_ut::test_vmcs_vm_exit_interruption_information_valid_bit()
{
    g_vmcs_fields[vmcs::vm_exit_interruption_information::addr] = 0x80001000UL;

    this->expect_true(vmcs::vm_exit_interruption_information::valid_bit::is_enabled());
    this->expect_true(vmcs::vm_exit_interruption_information::valid_bit::is_enabled_if_exists());

    this->expect_false(vmcs::vm_exit_interruption_information::valid_bit::is_disabled());
    this->expect_false(vmcs::vm_exit_interruption_information::valid_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_vm_exit_interruption_error_code()
{
    g_vmcs_fields[vmcs::vm_exit_interruption_error_code::addr] = 1UL;

    this->expect_true(vmcs::vm_exit_interruption_error_code::exists());
    this->expect_true(vmcs::vm_exit_interruption_error_code::get() == 1U);
    this->expect_true(vmcs::vm_exit_interruption_error_code::get_if_exists() == 1U);
}

void
vmcs_ut::test_vmcs_idt_vectoring_information()
{
    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 1UL;

    this->expect_true(vmcs::idt_vectoring_information::exists());
    this->expect_true(vmcs::idt_vectoring_information::get() == 1UL);
    this->expect_true(vmcs::idt_vectoring_information::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_idt_vectoring_information_vector()
{
    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 0xFFFUL;

    this->expect_true(vmcs::idt_vectoring_information::vector::get() == 0xFFUL);
    this->expect_true(vmcs::idt_vectoring_information::vector::get_if_exists() == 0xFFUL);
}

void
vmcs_ut::test_vmcs_idt_vectoring_information_interruption_type()
{
    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 0xFFFUL;

    this->expect_true(vmcs::idt_vectoring_information::interruption_type::get() == 7UL);
    this->expect_true(vmcs::idt_vectoring_information::interruption_type::get_if_exists() == 7UL);
}

void
vmcs_ut::test_vmcs_idt_vectoring_information_error_code_valid()
{
    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 0xFFFUL;

    this->expect_true(vmcs::idt_vectoring_information::error_code_valid::is_enabled());
    this->expect_true(vmcs::idt_vectoring_information::error_code_valid::is_enabled_if_exists());

    this->expect_false(vmcs::idt_vectoring_information::error_code_valid::is_disabled());
    this->expect_false(vmcs::idt_vectoring_information::error_code_valid::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_idt_vectoring_information_reserved()
{
    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 0xEE000UL;

    this->expect_true(vmcs::idt_vectoring_information::reserved::get() == 0xEE000U);
    this->expect_true(vmcs::idt_vectoring_information::reserved::get_if_exists() == 0xEE000U);
}

void
vmcs_ut::test_vmcs_idt_vectoring_information_valid_bit()
{
    g_vmcs_fields[vmcs::idt_vectoring_information::addr] = 0x80001000UL;

    this->expect_true(vmcs::idt_vectoring_information::valid_bit::is_enabled());
    this->expect_true(vmcs::idt_vectoring_information::valid_bit::is_enabled_if_exists());

    this->expect_false(vmcs::idt_vectoring_information::valid_bit::is_disabled());
    this->expect_false(vmcs::idt_vectoring_information::valid_bit::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_idt_vectoring_error_code()
{
    g_vmcs_fields[vmcs::idt_vectoring_error_code::addr] = 1UL;

    this->expect_true(vmcs::idt_vectoring_error_code::exists());
    this->expect_true(vmcs::idt_vectoring_error_code::get() == 1U);
    this->expect_true(vmcs::idt_vectoring_error_code::get_if_exists() == 1U);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_length()
{
    g_vmcs_fields[vmcs::vm_exit_instruction_length::addr] = 1UL;

    this->expect_true(vmcs::vm_exit_instruction_length::exists());
    this->expect_true(vmcs::vm_exit_instruction_length::get() == 1U);
    this->expect_true(vmcs::vm_exit_instruction_length::get_if_exists() == 1U);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information()
{
    g_vmcs_fields[vmcs::vm_exit_instruction_information::addr] = 1UL;

    this->expect_true(vmcs::vm_exit_instruction_information::exists());
    this->expect_true(vmcs::vm_exit_instruction_information::get() == 1UL);
    this->expect_true(vmcs::vm_exit_instruction_information::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ins()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(ins::get_name() == ins::name);
    this->expect_true(ins::get() == 1UL);
    this->expect_true(ins::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ins_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ins::address_size::_16bit << ins::address_size::from;
    this->expect_true(ins::address_size::get() == ins::address_size::_16bit);

    g_vmcs_fields[addr] = ins::address_size::_32bit << ins::address_size::from;
    this->expect_true(ins::address_size::get_if_exists() == ins::address_size::_32bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_outs()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(outs::get_name() == outs::name);
    this->expect_true(outs::get() == 1UL);
    this->expect_true(outs::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_outs_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = outs::address_size::_16bit << outs::address_size::from;
    this->expect_true(outs::address_size::get() == outs::address_size::_16bit);

    g_vmcs_fields[addr] = outs::address_size::_32bit << outs::address_size::from;
    this->expect_true(outs::address_size::get_if_exists() == outs::address_size::_32bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_outs_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = outs::segment_register::ss << outs::segment_register::from;
    this->expect_true(outs::segment_register::get() == outs::segment_register::ss);

    g_vmcs_fields[addr] = outs::segment_register::cs << outs::segment_register::from;
    this->expect_true(outs::segment_register::get_if_exists() == outs::segment_register::cs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invept()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(invept::get_name() == invept::name);
    this->expect_true(invept::get() == 1UL);
    this->expect_true(invept::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invept_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::scaling::scale_by_2 << invept::scaling::from;
    this->expect_true(invept::scaling::get() == invept::scaling::scale_by_2);

    g_vmcs_fields[addr] = invept::scaling::scale_by_8 << invept::scaling::from;
    this->expect_true(invept::scaling::get_if_exists() == invept::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invept_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::address_size::_32bit << invept::address_size::from;
    this->expect_true(invept::address_size::get() == invept::address_size::_32bit);

    g_vmcs_fields[addr] = invept::address_size::_64bit << invept::address_size::from;
    this->expect_true(invept::address_size::get_if_exists() == invept::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invept_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::segment_register::cs << invept::segment_register::from;
    this->expect_true(invept::segment_register::get() == invept::segment_register::cs);

    g_vmcs_fields[addr] = invept::segment_register::gs << invept::segment_register::from;
    this->expect_true(invept::segment_register::get_if_exists() == invept::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invept_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::index_reg::rsi << invept::index_reg::from;
    this->expect_true(invept::index_reg::get() == invept::index_reg::rsi);

    g_vmcs_fields[addr] = invept::index_reg::r11 << invept::index_reg::from;
    this->expect_true(invept::index_reg::get_if_exists() == invept::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invept_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::index_reg_invalid::valid << invept::index_reg_invalid::from;
    this->expect_true(invept::index_reg_invalid::get() == invept::index_reg_invalid::valid);

    g_vmcs_fields[addr] = invept::index_reg_invalid::invalid << invept::index_reg_invalid::from;
    this->expect_true(invept::index_reg_invalid::get_if_exists() == invept::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invept_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::base_reg::rdi << invept::base_reg::from;
    this->expect_true(invept::base_reg::get() == invept::base_reg::rdi);

    g_vmcs_fields[addr] = invept::base_reg::rcx << invept::base_reg::from;
    this->expect_true(invept::base_reg::get_if_exists() == invept::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invept_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::base_reg_invalid::valid << invept::base_reg_invalid::from;
    this->expect_true(invept::base_reg_invalid::get() == invept::base_reg_invalid::valid);

    g_vmcs_fields[addr] = invept::base_reg_invalid::invalid << invept::base_reg_invalid::from;
    this->expect_true(invept::base_reg_invalid::get_if_exists() == invept::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invept_reg2()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invept::reg2::rdx << invept::reg2::from;
    this->expect_true(invept::reg2::get() == invept::reg2::rdx);

    g_vmcs_fields[addr] = invept::reg2::rsp << invept::reg2::from;
    this->expect_true(invept::reg2::get_if_exists() == invept::reg2::rsp);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invpcid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(invpcid::get_name() == invpcid::name);
    this->expect_true(invpcid::get() == 1UL);
    this->expect_true(invpcid::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invpcid_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::scaling::scale_by_2 << invpcid::scaling::from;
    this->expect_true(invpcid::scaling::get() == invpcid::scaling::scale_by_2);

    g_vmcs_fields[addr] = invpcid::scaling::scale_by_8 << invpcid::scaling::from;
    this->expect_true(invpcid::scaling::get_if_exists() == invpcid::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invpcid_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::address_size::_32bit << invpcid::address_size::from;
    this->expect_true(invpcid::address_size::get() == invpcid::address_size::_32bit);

    g_vmcs_fields[addr] = invpcid::address_size::_64bit << invpcid::address_size::from;
    this->expect_true(invpcid::address_size::get_if_exists() == invpcid::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invpcid_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::segment_register::cs << invpcid::segment_register::from;
    this->expect_true(invpcid::segment_register::get() == invpcid::segment_register::cs);

    g_vmcs_fields[addr] = invpcid::segment_register::gs << invpcid::segment_register::from;
    this->expect_true(invpcid::segment_register::get_if_exists() == invpcid::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invpcid_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::index_reg::rsi << invpcid::index_reg::from;
    this->expect_true(invpcid::index_reg::get() == invpcid::index_reg::rsi);

    g_vmcs_fields[addr] = invpcid::index_reg::r11 << invpcid::index_reg::from;
    this->expect_true(invpcid::index_reg::get_if_exists() == invpcid::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invpcid_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::index_reg_invalid::valid << invpcid::index_reg_invalid::from;
    this->expect_true(invpcid::index_reg_invalid::get() == invpcid::index_reg_invalid::valid);

    g_vmcs_fields[addr] = invpcid::index_reg_invalid::invalid << invpcid::index_reg_invalid::from;
    this->expect_true(invpcid::index_reg_invalid::get_if_exists() == invpcid::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invpcid_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::base_reg::rdi << invpcid::base_reg::from;
    this->expect_true(invpcid::base_reg::get() == invpcid::base_reg::rdi);

    g_vmcs_fields[addr] = invpcid::base_reg::rcx << invpcid::base_reg::from;
    this->expect_true(invpcid::base_reg::get_if_exists() == invpcid::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invpcid_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::base_reg_invalid::valid << invpcid::base_reg_invalid::from;
    this->expect_true(invpcid::base_reg_invalid::get() == invpcid::base_reg_invalid::valid);

    g_vmcs_fields[addr] = invpcid::base_reg_invalid::invalid << invpcid::base_reg_invalid::from;
    this->expect_true(invpcid::base_reg_invalid::get_if_exists() == invpcid::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invpcid_reg2()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invpcid::reg2::rdx << invpcid::reg2::from;
    this->expect_true(invpcid::reg2::get() == invpcid::reg2::rdx);

    g_vmcs_fields[addr] = invpcid::reg2::rsp << invpcid::reg2::from;
    this->expect_true(invpcid::reg2::get_if_exists() == invpcid::reg2::rsp);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invvpid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(invvpid::get_name() == invvpid::name);
    this->expect_true(invvpid::get() == 1UL);
    this->expect_true(invvpid::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invvpid_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::scaling::scale_by_2 << invvpid::scaling::from;
    this->expect_true(invvpid::scaling::get() == invvpid::scaling::scale_by_2);

    g_vmcs_fields[addr] = invvpid::scaling::scale_by_8 << invvpid::scaling::from;
    this->expect_true(invvpid::scaling::get_if_exists() == invvpid::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invvpid_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::address_size::_32bit << invvpid::address_size::from;
    this->expect_true(invvpid::address_size::get() == invvpid::address_size::_32bit);

    g_vmcs_fields[addr] = invvpid::address_size::_64bit << invvpid::address_size::from;
    this->expect_true(invvpid::address_size::get_if_exists() == invvpid::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invvpid_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::segment_register::cs << invvpid::segment_register::from;
    this->expect_true(invvpid::segment_register::get() == invvpid::segment_register::cs);

    g_vmcs_fields[addr] = invvpid::segment_register::gs << invvpid::segment_register::from;
    this->expect_true(invvpid::segment_register::get_if_exists() == invvpid::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invvpid_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::index_reg::rsi << invvpid::index_reg::from;
    this->expect_true(invvpid::index_reg::get() == invvpid::index_reg::rsi);

    g_vmcs_fields[addr] = invvpid::index_reg::r11 << invvpid::index_reg::from;
    this->expect_true(invvpid::index_reg::get_if_exists() == invvpid::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invvpid_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::index_reg_invalid::valid << invvpid::index_reg_invalid::from;
    this->expect_true(invvpid::index_reg_invalid::get() == invvpid::index_reg_invalid::valid);

    g_vmcs_fields[addr] = invvpid::index_reg_invalid::invalid << invvpid::index_reg_invalid::from;
    this->expect_true(invvpid::index_reg_invalid::get_if_exists() == invvpid::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invvpid_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::base_reg::rdi << invvpid::base_reg::from;
    this->expect_true(invvpid::base_reg::get() == invvpid::base_reg::rdi);

    g_vmcs_fields[addr] = invvpid::base_reg::rcx << invvpid::base_reg::from;
    this->expect_true(invvpid::base_reg::get_if_exists() == invvpid::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invvpid_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::base_reg_invalid::valid << invvpid::base_reg_invalid::from;
    this->expect_true(invvpid::base_reg_invalid::get() == invvpid::base_reg_invalid::valid);

    g_vmcs_fields[addr] = invvpid::base_reg_invalid::invalid << invvpid::base_reg_invalid::from;
    this->expect_true(invvpid::base_reg_invalid::get_if_exists() == invvpid::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_invvpid_reg2()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = invvpid::reg2::rdx << invvpid::reg2::from;
    this->expect_true(invvpid::reg2::get() == invvpid::reg2::rdx);

    g_vmcs_fields[addr] = invvpid::reg2::rsp << invvpid::reg2::from;
    this->expect_true(invvpid::reg2::get_if_exists() == invvpid::reg2::rsp);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lidt()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(lidt::get_name() == lidt::name);
    this->expect_true(lidt::get() == 1UL);
    this->expect_true(lidt::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lidt_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::scaling::scale_by_2 << lidt::scaling::from;
    this->expect_true(lidt::scaling::get() == lidt::scaling::scale_by_2);

    g_vmcs_fields[addr] = lidt::scaling::scale_by_8 << lidt::scaling::from;
    this->expect_true(lidt::scaling::get_if_exists() == lidt::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lidt_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::address_size::_32bit << lidt::address_size::from;
    this->expect_true(lidt::address_size::get() == lidt::address_size::_32bit);

    g_vmcs_fields[addr] = lidt::address_size::_64bit << lidt::address_size::from;
    this->expect_true(lidt::address_size::get_if_exists() == lidt::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lidt_operand_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::operand_size::_16bit << lidt::operand_size::from;
    this->expect_true(lidt::operand_size::get() == lidt::operand_size::_16bit);

    g_vmcs_fields[addr] = lidt::operand_size::_32bit << lidt::operand_size::from;
    this->expect_true(lidt::operand_size::get_if_exists() == lidt::operand_size::_32bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lidt_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::segment_register::cs << lidt::segment_register::from;
    this->expect_true(lidt::segment_register::get() == lidt::segment_register::cs);

    g_vmcs_fields[addr] = lidt::segment_register::gs << lidt::segment_register::from;
    this->expect_true(lidt::segment_register::get_if_exists() == lidt::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lidt_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::index_reg::rsi << lidt::index_reg::from;
    this->expect_true(lidt::index_reg::get() == lidt::index_reg::rsi);

    g_vmcs_fields[addr] = lidt::index_reg::r11 << lidt::index_reg::from;
    this->expect_true(lidt::index_reg::get_if_exists() == lidt::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lidt_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::index_reg_invalid::valid << lidt::index_reg_invalid::from;
    this->expect_true(lidt::index_reg_invalid::get() == lidt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = lidt::index_reg_invalid::invalid << lidt::index_reg_invalid::from;
    this->expect_true(lidt::index_reg_invalid::get_if_exists() == lidt::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lidt_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::base_reg::rdi << lidt::base_reg::from;
    this->expect_true(lidt::base_reg::get() == lidt::base_reg::rdi);

    g_vmcs_fields[addr] = lidt::base_reg::rcx << lidt::base_reg::from;
    this->expect_true(lidt::base_reg::get_if_exists() == lidt::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lidt_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::base_reg_invalid::valid << lidt::base_reg_invalid::from;
    this->expect_true(lidt::base_reg_invalid::get() == lidt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = lidt::base_reg_invalid::invalid << lidt::base_reg_invalid::from;
    this->expect_true(lidt::base_reg_invalid::get_if_exists() == lidt::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lidt_instruction_identity()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lidt::instruction_identity::sgdt << lidt::instruction_identity::from;
    this->expect_true(lidt::instruction_identity::get() == lidt::instruction_identity::sgdt);

    g_vmcs_fields[addr] = lidt::instruction_identity::lidt << lidt::instruction_identity::from;
    this->expect_true(lidt::instruction_identity::get_if_exists() == lidt::instruction_identity::lidt);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lgdt()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(lgdt::get_name() == lgdt::name);
    this->expect_true(lgdt::get() == 1UL);
    this->expect_true(lgdt::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lgdt_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::scaling::scale_by_2 << lgdt::scaling::from;
    this->expect_true(lgdt::scaling::get() == lgdt::scaling::scale_by_2);

    g_vmcs_fields[addr] = lgdt::scaling::scale_by_8 << lgdt::scaling::from;
    this->expect_true(lgdt::scaling::get_if_exists() == lgdt::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lgdt_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::address_size::_32bit << lgdt::address_size::from;
    this->expect_true(lgdt::address_size::get() == lgdt::address_size::_32bit);

    g_vmcs_fields[addr] = lgdt::address_size::_64bit << lgdt::address_size::from;
    this->expect_true(lgdt::address_size::get_if_exists() == lgdt::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lgdt_operand_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::operand_size::_16bit << lgdt::operand_size::from;
    this->expect_true(lgdt::operand_size::get() == lgdt::operand_size::_16bit);

    g_vmcs_fields[addr] = lgdt::operand_size::_32bit << lgdt::operand_size::from;
    this->expect_true(lgdt::operand_size::get_if_exists() == lgdt::operand_size::_32bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lgdt_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::segment_register::cs << lgdt::segment_register::from;
    this->expect_true(lgdt::segment_register::get() == lgdt::segment_register::cs);

    g_vmcs_fields[addr] = lgdt::segment_register::gs << lgdt::segment_register::from;
    this->expect_true(lgdt::segment_register::get_if_exists() == lgdt::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lgdt_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::index_reg::rsi << lgdt::index_reg::from;
    this->expect_true(lgdt::index_reg::get() == lgdt::index_reg::rsi);

    g_vmcs_fields[addr] = lgdt::index_reg::r11 << lgdt::index_reg::from;
    this->expect_true(lgdt::index_reg::get_if_exists() == lgdt::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lgdt_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::index_reg_invalid::valid << lgdt::index_reg_invalid::from;
    this->expect_true(lgdt::index_reg_invalid::get() == lgdt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = lgdt::index_reg_invalid::invalid << lgdt::index_reg_invalid::from;
    this->expect_true(lgdt::index_reg_invalid::get_if_exists() == lgdt::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lgdt_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::base_reg::rdi << lgdt::base_reg::from;
    this->expect_true(lgdt::base_reg::get() == lgdt::base_reg::rdi);

    g_vmcs_fields[addr] = lgdt::base_reg::rcx << lgdt::base_reg::from;
    this->expect_true(lgdt::base_reg::get_if_exists() == lgdt::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lgdt_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::base_reg_invalid::valid << lgdt::base_reg_invalid::from;
    this->expect_true(lgdt::base_reg_invalid::get() == lgdt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = lgdt::base_reg_invalid::invalid << lgdt::base_reg_invalid::from;
    this->expect_true(lgdt::base_reg_invalid::get_if_exists() == lgdt::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lgdt_instruction_identity()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lgdt::instruction_identity::sgdt << lgdt::instruction_identity::from;
    this->expect_true(lgdt::instruction_identity::get() == lgdt::instruction_identity::sgdt);

    g_vmcs_fields[addr] = lgdt::instruction_identity::lgdt << lgdt::instruction_identity::from;
    this->expect_true(lgdt::instruction_identity::get_if_exists() == lgdt::instruction_identity::lgdt);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sidt()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(sidt::get_name() == sidt::name);
    this->expect_true(sidt::get() == 1UL);
    this->expect_true(sidt::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sidt_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::scaling::scale_by_2 << sidt::scaling::from;
    this->expect_true(sidt::scaling::get() == sidt::scaling::scale_by_2);

    g_vmcs_fields[addr] = sidt::scaling::scale_by_8 << sidt::scaling::from;
    this->expect_true(sidt::scaling::get_if_exists() == sidt::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sidt_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::address_size::_32bit << sidt::address_size::from;
    this->expect_true(sidt::address_size::get() == sidt::address_size::_32bit);

    g_vmcs_fields[addr] = sidt::address_size::_64bit << sidt::address_size::from;
    this->expect_true(sidt::address_size::get_if_exists() == sidt::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sidt_operand_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::operand_size::_16bit << sidt::operand_size::from;
    this->expect_true(sidt::operand_size::get() == sidt::operand_size::_16bit);

    g_vmcs_fields[addr] = sidt::operand_size::_32bit << sidt::operand_size::from;
    this->expect_true(sidt::operand_size::get_if_exists() == sidt::operand_size::_32bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sidt_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::segment_register::cs << sidt::segment_register::from;
    this->expect_true(sidt::segment_register::get() == sidt::segment_register::cs);

    g_vmcs_fields[addr] = sidt::segment_register::gs << sidt::segment_register::from;
    this->expect_true(sidt::segment_register::get_if_exists() == sidt::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sidt_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::index_reg::rsi << sidt::index_reg::from;
    this->expect_true(sidt::index_reg::get() == sidt::index_reg::rsi);

    g_vmcs_fields[addr] = sidt::index_reg::r11 << sidt::index_reg::from;
    this->expect_true(sidt::index_reg::get_if_exists() == sidt::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sidt_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::index_reg_invalid::valid << sidt::index_reg_invalid::from;
    this->expect_true(sidt::index_reg_invalid::get() == sidt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = sidt::index_reg_invalid::invalid << sidt::index_reg_invalid::from;
    this->expect_true(sidt::index_reg_invalid::get_if_exists() == sidt::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sidt_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::base_reg::rdi << sidt::base_reg::from;
    this->expect_true(sidt::base_reg::get() == sidt::base_reg::rdi);

    g_vmcs_fields[addr] = sidt::base_reg::rcx << sidt::base_reg::from;
    this->expect_true(sidt::base_reg::get_if_exists() == sidt::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sidt_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::base_reg_invalid::valid << sidt::base_reg_invalid::from;
    this->expect_true(sidt::base_reg_invalid::get() == sidt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = sidt::base_reg_invalid::invalid << sidt::base_reg_invalid::from;
    this->expect_true(sidt::base_reg_invalid::get_if_exists() == sidt::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sidt_instruction_identity()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sidt::instruction_identity::sgdt << sidt::instruction_identity::from;
    this->expect_true(sidt::instruction_identity::get() == sidt::instruction_identity::sgdt);

    g_vmcs_fields[addr] = sidt::instruction_identity::sidt << sidt::instruction_identity::from;
    this->expect_true(sidt::instruction_identity::get_if_exists() == sidt::instruction_identity::sidt);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sgdt()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(sgdt::get_name() == sgdt::name);
    this->expect_true(sgdt::get() == 1UL);
    this->expect_true(sgdt::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sgdt_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::scaling::scale_by_2 << sgdt::scaling::from;
    this->expect_true(sgdt::scaling::get() == sgdt::scaling::scale_by_2);

    g_vmcs_fields[addr] = sgdt::scaling::scale_by_8 << sgdt::scaling::from;
    this->expect_true(sgdt::scaling::get_if_exists() == sgdt::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sgdt_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::address_size::_32bit << sgdt::address_size::from;
    this->expect_true(sgdt::address_size::get() == sgdt::address_size::_32bit);

    g_vmcs_fields[addr] = sgdt::address_size::_64bit << sgdt::address_size::from;
    this->expect_true(sgdt::address_size::get_if_exists() == sgdt::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sgdt_operand_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::operand_size::_16bit << sgdt::operand_size::from;
    this->expect_true(sgdt::operand_size::get() == sgdt::operand_size::_16bit);

    g_vmcs_fields[addr] = sgdt::operand_size::_32bit << sgdt::operand_size::from;
    this->expect_true(sgdt::operand_size::get_if_exists() == sgdt::operand_size::_32bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sgdt_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::segment_register::cs << sgdt::segment_register::from;
    this->expect_true(sgdt::segment_register::get() == sgdt::segment_register::cs);

    g_vmcs_fields[addr] = sgdt::segment_register::gs << sgdt::segment_register::from;
    this->expect_true(sgdt::segment_register::get_if_exists() == sgdt::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sgdt_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::index_reg::rsi << sgdt::index_reg::from;
    this->expect_true(sgdt::index_reg::get() == sgdt::index_reg::rsi);

    g_vmcs_fields[addr] = sgdt::index_reg::r11 << sgdt::index_reg::from;
    this->expect_true(sgdt::index_reg::get_if_exists() == sgdt::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sgdt_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::index_reg_invalid::valid << sgdt::index_reg_invalid::from;
    this->expect_true(sgdt::index_reg_invalid::get() == sgdt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = sgdt::index_reg_invalid::invalid << sgdt::index_reg_invalid::from;
    this->expect_true(sgdt::index_reg_invalid::get_if_exists() == sgdt::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sgdt_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::base_reg::rdi << sgdt::base_reg::from;
    this->expect_true(sgdt::base_reg::get() == sgdt::base_reg::rdi);

    g_vmcs_fields[addr] = sgdt::base_reg::rcx << sgdt::base_reg::from;
    this->expect_true(sgdt::base_reg::get_if_exists() == sgdt::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sgdt_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::base_reg_invalid::valid << sgdt::base_reg_invalid::from;
    this->expect_true(sgdt::base_reg_invalid::get() == sgdt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = sgdt::base_reg_invalid::invalid << sgdt::base_reg_invalid::from;
    this->expect_true(sgdt::base_reg_invalid::get_if_exists() == sgdt::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sgdt_instruction_identity()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sgdt::instruction_identity::sgdt << sgdt::instruction_identity::from;
    this->expect_true(sgdt::instruction_identity::get() == sgdt::instruction_identity::sgdt);

    g_vmcs_fields[addr] = sgdt::instruction_identity::sgdt << sgdt::instruction_identity::from;
    this->expect_true(sgdt::instruction_identity::get_if_exists() == sgdt::instruction_identity::sgdt);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(lldt::get_name() == lldt::name);
    this->expect_true(lldt::get() == 1UL);
    this->expect_true(lldt::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::scaling::scale_by_2 << lldt::scaling::from;
    this->expect_true(lldt::scaling::get() == lldt::scaling::scale_by_2);

    g_vmcs_fields[addr] = lldt::scaling::scale_by_8 << lldt::scaling::from;
    this->expect_true(lldt::scaling::get_if_exists() == lldt::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt_reg1()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::reg1::rbp << lldt::reg1::from;
    this->expect_true(lldt::reg1::get() == lldt::reg1::rbp);

    g_vmcs_fields[addr] = lldt::reg1::r13 << lldt::reg1::from;
    this->expect_true(lldt::reg1::get_if_exists() == lldt::reg1::r13);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::address_size::_32bit << lldt::address_size::from;
    this->expect_true(lldt::address_size::get() == lldt::address_size::_32bit);

    g_vmcs_fields[addr] = lldt::address_size::_64bit << lldt::address_size::from;
    this->expect_true(lldt::address_size::get_if_exists() == lldt::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt_mem_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::mem_reg::mem << lldt::mem_reg::from;
    this->expect_true(lldt::mem_reg::get() == lldt::mem_reg::mem);

    g_vmcs_fields[addr] = lldt::mem_reg::reg << lldt::mem_reg::from;
    this->expect_true(lldt::mem_reg::get_if_exists() == lldt::mem_reg::reg);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::segment_register::cs << lldt::segment_register::from;
    this->expect_true(lldt::segment_register::get() == lldt::segment_register::cs);

    g_vmcs_fields[addr] = lldt::segment_register::gs << lldt::segment_register::from;
    this->expect_true(lldt::segment_register::get_if_exists() == lldt::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::index_reg::rsi << lldt::index_reg::from;
    this->expect_true(lldt::index_reg::get() == lldt::index_reg::rsi);

    g_vmcs_fields[addr] = lldt::index_reg::r11 << lldt::index_reg::from;
    this->expect_true(lldt::index_reg::get_if_exists() == lldt::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::index_reg_invalid::valid << lldt::index_reg_invalid::from;
    this->expect_true(lldt::index_reg_invalid::get() == lldt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = lldt::index_reg_invalid::invalid << lldt::index_reg_invalid::from;
    this->expect_true(lldt::index_reg_invalid::get_if_exists() == lldt::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::base_reg::rdi << lldt::base_reg::from;
    this->expect_true(lldt::base_reg::get() == lldt::base_reg::rdi);

    g_vmcs_fields[addr] = lldt::base_reg::rcx << lldt::base_reg::from;
    this->expect_true(lldt::base_reg::get_if_exists() == lldt::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::base_reg_invalid::valid << lldt::base_reg_invalid::from;
    this->expect_true(lldt::base_reg_invalid::get() == lldt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = lldt::base_reg_invalid::invalid << lldt::base_reg_invalid::from;
    this->expect_true(lldt::base_reg_invalid::get_if_exists() == lldt::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_lldt_instruction_identity()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = lldt::instruction_identity::sldt << lldt::instruction_identity::from;
    this->expect_true(lldt::instruction_identity::get() == lldt::instruction_identity::sldt);

    g_vmcs_fields[addr] = lldt::instruction_identity::lldt << lldt::instruction_identity::from;
    this->expect_true(lldt::instruction_identity::get_if_exists() == lldt::instruction_identity::lldt);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(ltr::get_name() == ltr::name);
    this->expect_true(ltr::get() == 1UL);
    this->expect_true(ltr::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::scaling::scale_by_2 << ltr::scaling::from;
    this->expect_true(ltr::scaling::get() == ltr::scaling::scale_by_2);

    g_vmcs_fields[addr] = ltr::scaling::scale_by_8 << ltr::scaling::from;
    this->expect_true(ltr::scaling::get_if_exists() == ltr::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr_reg1()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::reg1::rbp << ltr::reg1::from;
    this->expect_true(ltr::reg1::get() == ltr::reg1::rbp);

    g_vmcs_fields[addr] = ltr::reg1::r13 << ltr::reg1::from;
    this->expect_true(ltr::reg1::get_if_exists() == ltr::reg1::r13);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::address_size::_32bit << ltr::address_size::from;
    this->expect_true(ltr::address_size::get() == ltr::address_size::_32bit);

    g_vmcs_fields[addr] = ltr::address_size::_64bit << ltr::address_size::from;
    this->expect_true(ltr::address_size::get_if_exists() == ltr::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr_mem_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::mem_reg::mem << ltr::mem_reg::from;
    this->expect_true(ltr::mem_reg::get() == ltr::mem_reg::mem);

    g_vmcs_fields[addr] = ltr::mem_reg::reg << ltr::mem_reg::from;
    this->expect_true(ltr::mem_reg::get_if_exists() == ltr::mem_reg::reg);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::segment_register::cs << ltr::segment_register::from;
    this->expect_true(ltr::segment_register::get() == ltr::segment_register::cs);

    g_vmcs_fields[addr] = ltr::segment_register::gs << ltr::segment_register::from;
    this->expect_true(ltr::segment_register::get_if_exists() == ltr::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::index_reg::rsi << ltr::index_reg::from;
    this->expect_true(ltr::index_reg::get() == ltr::index_reg::rsi);

    g_vmcs_fields[addr] = ltr::index_reg::r11 << ltr::index_reg::from;
    this->expect_true(ltr::index_reg::get_if_exists() == ltr::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::index_reg_invalid::valid << ltr::index_reg_invalid::from;
    this->expect_true(ltr::index_reg_invalid::get() == ltr::index_reg_invalid::valid);

    g_vmcs_fields[addr] = ltr::index_reg_invalid::invalid << ltr::index_reg_invalid::from;
    this->expect_true(ltr::index_reg_invalid::get_if_exists() == ltr::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::base_reg::rdi << ltr::base_reg::from;
    this->expect_true(ltr::base_reg::get() == ltr::base_reg::rdi);

    g_vmcs_fields[addr] = ltr::base_reg::rcx << ltr::base_reg::from;
    this->expect_true(ltr::base_reg::get_if_exists() == ltr::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::base_reg_invalid::valid << ltr::base_reg_invalid::from;
    this->expect_true(ltr::base_reg_invalid::get() == ltr::base_reg_invalid::valid);

    g_vmcs_fields[addr] = ltr::base_reg_invalid::invalid << ltr::base_reg_invalid::from;
    this->expect_true(ltr::base_reg_invalid::get_if_exists() == ltr::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_ltr_instruction_identity()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = ltr::instruction_identity::sldt << ltr::instruction_identity::from;
    this->expect_true(ltr::instruction_identity::get() == ltr::instruction_identity::sldt);

    g_vmcs_fields[addr] = ltr::instruction_identity::ltr << ltr::instruction_identity::from;
    this->expect_true(ltr::instruction_identity::get_if_exists() == ltr::instruction_identity::ltr);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(sldt::get_name() == sldt::name);
    this->expect_true(sldt::get() == 1UL);
    this->expect_true(sldt::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::scaling::scale_by_2 << sldt::scaling::from;
    this->expect_true(sldt::scaling::get() == sldt::scaling::scale_by_2);

    g_vmcs_fields[addr] = sldt::scaling::scale_by_8 << sldt::scaling::from;
    this->expect_true(sldt::scaling::get_if_exists() == sldt::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt_reg1()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::reg1::rbp << sldt::reg1::from;
    this->expect_true(sldt::reg1::get() == sldt::reg1::rbp);

    g_vmcs_fields[addr] = sldt::reg1::r13 << sldt::reg1::from;
    this->expect_true(sldt::reg1::get_if_exists() == sldt::reg1::r13);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::address_size::_32bit << sldt::address_size::from;
    this->expect_true(sldt::address_size::get() == sldt::address_size::_32bit);

    g_vmcs_fields[addr] = sldt::address_size::_64bit << sldt::address_size::from;
    this->expect_true(sldt::address_size::get_if_exists() == sldt::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt_mem_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::mem_reg::mem << sldt::mem_reg::from;
    this->expect_true(sldt::mem_reg::get() == sldt::mem_reg::mem);

    g_vmcs_fields[addr] = sldt::mem_reg::reg << sldt::mem_reg::from;
    this->expect_true(sldt::mem_reg::get_if_exists() == sldt::mem_reg::reg);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::segment_register::cs << sldt::segment_register::from;
    this->expect_true(sldt::segment_register::get() == sldt::segment_register::cs);

    g_vmcs_fields[addr] = sldt::segment_register::gs << sldt::segment_register::from;
    this->expect_true(sldt::segment_register::get_if_exists() == sldt::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::index_reg::rsi << sldt::index_reg::from;
    this->expect_true(sldt::index_reg::get() == sldt::index_reg::rsi);

    g_vmcs_fields[addr] = sldt::index_reg::r11 << sldt::index_reg::from;
    this->expect_true(sldt::index_reg::get_if_exists() == sldt::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::index_reg_invalid::valid << sldt::index_reg_invalid::from;
    this->expect_true(sldt::index_reg_invalid::get() == sldt::index_reg_invalid::valid);

    g_vmcs_fields[addr] = sldt::index_reg_invalid::invalid << sldt::index_reg_invalid::from;
    this->expect_true(sldt::index_reg_invalid::get_if_exists() == sldt::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::base_reg::rdi << sldt::base_reg::from;
    this->expect_true(sldt::base_reg::get() == sldt::base_reg::rdi);

    g_vmcs_fields[addr] = sldt::base_reg::rcx << sldt::base_reg::from;
    this->expect_true(sldt::base_reg::get_if_exists() == sldt::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::base_reg_invalid::valid << sldt::base_reg_invalid::from;
    this->expect_true(sldt::base_reg_invalid::get() == sldt::base_reg_invalid::valid);

    g_vmcs_fields[addr] = sldt::base_reg_invalid::invalid << sldt::base_reg_invalid::from;
    this->expect_true(sldt::base_reg_invalid::get_if_exists() == sldt::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_sldt_instruction_identity()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = sldt::instruction_identity::sldt << sldt::instruction_identity::from;
    this->expect_true(sldt::instruction_identity::get() == sldt::instruction_identity::sldt);

    g_vmcs_fields[addr] = sldt::instruction_identity::ltr << sldt::instruction_identity::from;
    this->expect_true(sldt::instruction_identity::get_if_exists() == sldt::instruction_identity::ltr);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(str::get_name() == str::name);
    this->expect_true(str::get() == 1UL);
    this->expect_true(str::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::scaling::scale_by_2 << str::scaling::from;
    this->expect_true(str::scaling::get() == str::scaling::scale_by_2);

    g_vmcs_fields[addr] = str::scaling::scale_by_8 << str::scaling::from;
    this->expect_true(str::scaling::get_if_exists() == str::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str_reg1()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::reg1::rbp << str::reg1::from;
    this->expect_true(str::reg1::get() == str::reg1::rbp);

    g_vmcs_fields[addr] = str::reg1::r13 << str::reg1::from;
    this->expect_true(str::reg1::get_if_exists() == str::reg1::r13);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::address_size::_32bit << str::address_size::from;
    this->expect_true(str::address_size::get() == str::address_size::_32bit);

    g_vmcs_fields[addr] = str::address_size::_64bit << str::address_size::from;
    this->expect_true(str::address_size::get_if_exists() == str::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str_mem_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::mem_reg::mem << str::mem_reg::from;
    this->expect_true(str::mem_reg::get() == str::mem_reg::mem);

    g_vmcs_fields[addr] = str::mem_reg::reg << str::mem_reg::from;
    this->expect_true(str::mem_reg::get_if_exists() == str::mem_reg::reg);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::segment_register::cs << str::segment_register::from;
    this->expect_true(str::segment_register::get() == str::segment_register::cs);

    g_vmcs_fields[addr] = str::segment_register::gs << str::segment_register::from;
    this->expect_true(str::segment_register::get_if_exists() == str::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::index_reg::rsi << str::index_reg::from;
    this->expect_true(str::index_reg::get() == str::index_reg::rsi);

    g_vmcs_fields[addr] = str::index_reg::r11 << str::index_reg::from;
    this->expect_true(str::index_reg::get_if_exists() == str::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::index_reg_invalid::valid << str::index_reg_invalid::from;
    this->expect_true(str::index_reg_invalid::get() == str::index_reg_invalid::valid);

    g_vmcs_fields[addr] = str::index_reg_invalid::invalid << str::index_reg_invalid::from;
    this->expect_true(str::index_reg_invalid::get_if_exists() == str::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::base_reg::rdi << str::base_reg::from;
    this->expect_true(str::base_reg::get() == str::base_reg::rdi);

    g_vmcs_fields[addr] = str::base_reg::rcx << str::base_reg::from;
    this->expect_true(str::base_reg::get_if_exists() == str::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::base_reg_invalid::valid << str::base_reg_invalid::from;
    this->expect_true(str::base_reg_invalid::get() == str::base_reg_invalid::valid);

    g_vmcs_fields[addr] = str::base_reg_invalid::invalid << str::base_reg_invalid::from;
    this->expect_true(str::base_reg_invalid::get_if_exists() == str::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_str_instruction_identity()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = str::instruction_identity::sldt << str::instruction_identity::from;
    this->expect_true(str::instruction_identity::get() == str::instruction_identity::sldt);

    g_vmcs_fields[addr] = str::instruction_identity::str << str::instruction_identity::from;
    this->expect_true(str::instruction_identity::get_if_exists() == str::instruction_identity::str);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_rdrand()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(rdrand::get_name() == rdrand::name);
    this->expect_true(rdrand::get() == 1UL);
    this->expect_true(rdrand::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_rdrand_destination_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = rdrand::destination_register::rdx << rdrand::destination_register::from;
    this->expect_true(rdrand::destination_register::get() == rdrand::destination_register::rdx);

    g_vmcs_fields[addr] = rdrand::destination_register::r14 << rdrand::destination_register::from;
    this->expect_true(rdrand::destination_register::get_if_exists() == rdrand::destination_register::r14);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_rdrand_operand_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = rdrand::operand_size::_16bit << rdrand::operand_size::from;
    this->expect_true(rdrand::operand_size::get() == rdrand::operand_size::_16bit);

    g_vmcs_fields[addr] = rdrand::operand_size::_64bit << rdrand::operand_size::from;
    this->expect_true(rdrand::operand_size::get_if_exists() == rdrand::operand_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_rdseed()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(rdseed::get_name() == rdseed::name);
    this->expect_true(rdseed::get() == 1UL);
    this->expect_true(rdseed::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_rdseed_destination_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = rdseed::destination_register::rdx << rdseed::destination_register::from;
    this->expect_true(rdseed::destination_register::get() == rdseed::destination_register::rdx);

    g_vmcs_fields[addr] = rdseed::destination_register::r14 << rdseed::destination_register::from;
    this->expect_true(rdseed::destination_register::get_if_exists() == rdseed::destination_register::r14);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_rdseed_operand_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = rdseed::operand_size::_16bit << rdseed::operand_size::from;
    this->expect_true(rdseed::operand_size::get() == rdseed::operand_size::_16bit);

    g_vmcs_fields[addr] = rdseed::operand_size::_64bit << rdseed::operand_size::from;
    this->expect_true(rdseed::operand_size::get_if_exists() == rdseed::operand_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmclear()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(vmclear::get_name() == vmclear::name);
    this->expect_true(vmclear::get() == 1UL);
    this->expect_true(vmclear::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmclear_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::scaling::scale_by_2 << vmclear::scaling::from;
    this->expect_true(vmclear::scaling::get() == vmclear::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmclear::scaling::scale_by_8 << vmclear::scaling::from;
    this->expect_true(vmclear::scaling::get_if_exists() == vmclear::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmclear_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::address_size::_32bit << vmclear::address_size::from;
    this->expect_true(vmclear::address_size::get() == vmclear::address_size::_32bit);

    g_vmcs_fields[addr] = vmclear::address_size::_64bit << vmclear::address_size::from;
    this->expect_true(vmclear::address_size::get_if_exists() == vmclear::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmclear_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::segment_register::cs << vmclear::segment_register::from;
    this->expect_true(vmclear::segment_register::get() == vmclear::segment_register::cs);

    g_vmcs_fields[addr] = vmclear::segment_register::gs << vmclear::segment_register::from;
    this->expect_true(vmclear::segment_register::get_if_exists() == vmclear::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmclear_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::index_reg::rsi << vmclear::index_reg::from;
    this->expect_true(vmclear::index_reg::get() == vmclear::index_reg::rsi);

    g_vmcs_fields[addr] = vmclear::index_reg::r11 << vmclear::index_reg::from;
    this->expect_true(vmclear::index_reg::get_if_exists() == vmclear::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmclear_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::index_reg_invalid::valid << vmclear::index_reg_invalid::from;
    this->expect_true(vmclear::index_reg_invalid::get() == vmclear::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmclear::index_reg_invalid::invalid << vmclear::index_reg_invalid::from;
    this->expect_true(vmclear::index_reg_invalid::get_if_exists() == vmclear::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmclear_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::base_reg::rdi << vmclear::base_reg::from;
    this->expect_true(vmclear::base_reg::get() == vmclear::base_reg::rdi);

    g_vmcs_fields[addr] = vmclear::base_reg::rcx << vmclear::base_reg::from;
    this->expect_true(vmclear::base_reg::get_if_exists() == vmclear::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmclear_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmclear::base_reg_invalid::valid << vmclear::base_reg_invalid::from;
    this->expect_true(vmclear::base_reg_invalid::get() == vmclear::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmclear::base_reg_invalid::invalid << vmclear::base_reg_invalid::from;
    this->expect_true(vmclear::base_reg_invalid::get_if_exists() == vmclear::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrld()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(vmptrld::get_name() == vmptrld::name);
    this->expect_true(vmptrld::get() == 1UL);
    this->expect_true(vmptrld::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrld_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::scaling::scale_by_2 << vmptrld::scaling::from;
    this->expect_true(vmptrld::scaling::get() == vmptrld::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmptrld::scaling::scale_by_8 << vmptrld::scaling::from;
    this->expect_true(vmptrld::scaling::get_if_exists() == vmptrld::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrld_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::address_size::_32bit << vmptrld::address_size::from;
    this->expect_true(vmptrld::address_size::get() == vmptrld::address_size::_32bit);

    g_vmcs_fields[addr] = vmptrld::address_size::_64bit << vmptrld::address_size::from;
    this->expect_true(vmptrld::address_size::get_if_exists() == vmptrld::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrld_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::segment_register::cs << vmptrld::segment_register::from;
    this->expect_true(vmptrld::segment_register::get() == vmptrld::segment_register::cs);

    g_vmcs_fields[addr] = vmptrld::segment_register::gs << vmptrld::segment_register::from;
    this->expect_true(vmptrld::segment_register::get_if_exists() == vmptrld::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrld_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::index_reg::rsi << vmptrld::index_reg::from;
    this->expect_true(vmptrld::index_reg::get() == vmptrld::index_reg::rsi);

    g_vmcs_fields[addr] = vmptrld::index_reg::r11 << vmptrld::index_reg::from;
    this->expect_true(vmptrld::index_reg::get_if_exists() == vmptrld::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrld_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::index_reg_invalid::valid << vmptrld::index_reg_invalid::from;
    this->expect_true(vmptrld::index_reg_invalid::get() == vmptrld::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmptrld::index_reg_invalid::invalid << vmptrld::index_reg_invalid::from;
    this->expect_true(vmptrld::index_reg_invalid::get_if_exists() == vmptrld::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrld_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::base_reg::rdi << vmptrld::base_reg::from;
    this->expect_true(vmptrld::base_reg::get() == vmptrld::base_reg::rdi);

    g_vmcs_fields[addr] = vmptrld::base_reg::rcx << vmptrld::base_reg::from;
    this->expect_true(vmptrld::base_reg::get_if_exists() == vmptrld::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrld_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrld::base_reg_invalid::valid << vmptrld::base_reg_invalid::from;
    this->expect_true(vmptrld::base_reg_invalid::get() == vmptrld::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmptrld::base_reg_invalid::invalid << vmptrld::base_reg_invalid::from;
    this->expect_true(vmptrld::base_reg_invalid::get_if_exists() == vmptrld::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrst()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(vmptrst::get_name() == vmptrst::name);
    this->expect_true(vmptrst::get() == 1UL);
    this->expect_true(vmptrst::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrst_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::scaling::scale_by_2 << vmptrst::scaling::from;
    this->expect_true(vmptrst::scaling::get() == vmptrst::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmptrst::scaling::scale_by_8 << vmptrst::scaling::from;
    this->expect_true(vmptrst::scaling::get_if_exists() == vmptrst::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrst_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::address_size::_32bit << vmptrst::address_size::from;
    this->expect_true(vmptrst::address_size::get() == vmptrst::address_size::_32bit);

    g_vmcs_fields[addr] = vmptrst::address_size::_64bit << vmptrst::address_size::from;
    this->expect_true(vmptrst::address_size::get_if_exists() == vmptrst::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrst_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::segment_register::cs << vmptrst::segment_register::from;
    this->expect_true(vmptrst::segment_register::get() == vmptrst::segment_register::cs);

    g_vmcs_fields[addr] = vmptrst::segment_register::gs << vmptrst::segment_register::from;
    this->expect_true(vmptrst::segment_register::get_if_exists() == vmptrst::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrst_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::index_reg::rsi << vmptrst::index_reg::from;
    this->expect_true(vmptrst::index_reg::get() == vmptrst::index_reg::rsi);

    g_vmcs_fields[addr] = vmptrst::index_reg::r11 << vmptrst::index_reg::from;
    this->expect_true(vmptrst::index_reg::get_if_exists() == vmptrst::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrst_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::index_reg_invalid::valid << vmptrst::index_reg_invalid::from;
    this->expect_true(vmptrst::index_reg_invalid::get() == vmptrst::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmptrst::index_reg_invalid::invalid << vmptrst::index_reg_invalid::from;
    this->expect_true(vmptrst::index_reg_invalid::get_if_exists() == vmptrst::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrst_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::base_reg::rdi << vmptrst::base_reg::from;
    this->expect_true(vmptrst::base_reg::get() == vmptrst::base_reg::rdi);

    g_vmcs_fields[addr] = vmptrst::base_reg::rcx << vmptrst::base_reg::from;
    this->expect_true(vmptrst::base_reg::get_if_exists() == vmptrst::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmptrst_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmptrst::base_reg_invalid::valid << vmptrst::base_reg_invalid::from;
    this->expect_true(vmptrst::base_reg_invalid::get() == vmptrst::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmptrst::base_reg_invalid::invalid << vmptrst::base_reg_invalid::from;
    this->expect_true(vmptrst::base_reg_invalid::get_if_exists() == vmptrst::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmxon()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(vmxon::get_name() == vmxon::name);
    this->expect_true(vmxon::get() == 1UL);
    this->expect_true(vmxon::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmxon_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::scaling::scale_by_2 << vmxon::scaling::from;
    this->expect_true(vmxon::scaling::get() == vmxon::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmxon::scaling::scale_by_8 << vmxon::scaling::from;
    this->expect_true(vmxon::scaling::get_if_exists() == vmxon::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmxon_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::address_size::_32bit << vmxon::address_size::from;
    this->expect_true(vmxon::address_size::get() == vmxon::address_size::_32bit);

    g_vmcs_fields[addr] = vmxon::address_size::_64bit << vmxon::address_size::from;
    this->expect_true(vmxon::address_size::get_if_exists() == vmxon::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmxon_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::segment_register::cs << vmxon::segment_register::from;
    this->expect_true(vmxon::segment_register::get() == vmxon::segment_register::cs);

    g_vmcs_fields[addr] = vmxon::segment_register::gs << vmxon::segment_register::from;
    this->expect_true(vmxon::segment_register::get_if_exists() == vmxon::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmxon_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::index_reg::rsi << vmxon::index_reg::from;
    this->expect_true(vmxon::index_reg::get() == vmxon::index_reg::rsi);

    g_vmcs_fields[addr] = vmxon::index_reg::r11 << vmxon::index_reg::from;
    this->expect_true(vmxon::index_reg::get_if_exists() == vmxon::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmxon_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::index_reg_invalid::valid << vmxon::index_reg_invalid::from;
    this->expect_true(vmxon::index_reg_invalid::get() == vmxon::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmxon::index_reg_invalid::invalid << vmxon::index_reg_invalid::from;
    this->expect_true(vmxon::index_reg_invalid::get_if_exists() == vmxon::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmxon_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::base_reg::rdi << vmxon::base_reg::from;
    this->expect_true(vmxon::base_reg::get() == vmxon::base_reg::rdi);

    g_vmcs_fields[addr] = vmxon::base_reg::rcx << vmxon::base_reg::from;
    this->expect_true(vmxon::base_reg::get_if_exists() == vmxon::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmxon_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmxon::base_reg_invalid::valid << vmxon::base_reg_invalid::from;
    this->expect_true(vmxon::base_reg_invalid::get() == vmxon::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmxon::base_reg_invalid::invalid << vmxon::base_reg_invalid::from;
    this->expect_true(vmxon::base_reg_invalid::get_if_exists() == vmxon::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xrstors()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(xrstors::get_name() == xrstors::name);
    this->expect_true(xrstors::get() == 1UL);
    this->expect_true(xrstors::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xrstors_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::scaling::scale_by_2 << xrstors::scaling::from;
    this->expect_true(xrstors::scaling::get() == xrstors::scaling::scale_by_2);

    g_vmcs_fields[addr] = xrstors::scaling::scale_by_8 << xrstors::scaling::from;
    this->expect_true(xrstors::scaling::get_if_exists() == xrstors::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xrstors_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::address_size::_32bit << xrstors::address_size::from;
    this->expect_true(xrstors::address_size::get() == xrstors::address_size::_32bit);

    g_vmcs_fields[addr] = xrstors::address_size::_64bit << xrstors::address_size::from;
    this->expect_true(xrstors::address_size::get_if_exists() == xrstors::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xrstors_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::segment_register::cs << xrstors::segment_register::from;
    this->expect_true(xrstors::segment_register::get() == xrstors::segment_register::cs);

    g_vmcs_fields[addr] = xrstors::segment_register::gs << xrstors::segment_register::from;
    this->expect_true(xrstors::segment_register::get_if_exists() == xrstors::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xrstors_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::index_reg::rsi << xrstors::index_reg::from;
    this->expect_true(xrstors::index_reg::get() == xrstors::index_reg::rsi);

    g_vmcs_fields[addr] = xrstors::index_reg::r11 << xrstors::index_reg::from;
    this->expect_true(xrstors::index_reg::get_if_exists() == xrstors::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xrstors_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::index_reg_invalid::valid << xrstors::index_reg_invalid::from;
    this->expect_true(xrstors::index_reg_invalid::get() == xrstors::index_reg_invalid::valid);

    g_vmcs_fields[addr] = xrstors::index_reg_invalid::invalid << xrstors::index_reg_invalid::from;
    this->expect_true(xrstors::index_reg_invalid::get_if_exists() == xrstors::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xrstors_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::base_reg::rdi << xrstors::base_reg::from;
    this->expect_true(xrstors::base_reg::get() == xrstors::base_reg::rdi);

    g_vmcs_fields[addr] = xrstors::base_reg::rcx << xrstors::base_reg::from;
    this->expect_true(xrstors::base_reg::get_if_exists() == xrstors::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xrstors_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xrstors::base_reg_invalid::valid << xrstors::base_reg_invalid::from;
    this->expect_true(xrstors::base_reg_invalid::get() == xrstors::base_reg_invalid::valid);

    g_vmcs_fields[addr] = xrstors::base_reg_invalid::invalid << xrstors::base_reg_invalid::from;
    this->expect_true(xrstors::base_reg_invalid::get_if_exists() == xrstors::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xsaves()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(xsaves::get_name() == xsaves::name);
    this->expect_true(xsaves::get() == 1UL);
    this->expect_true(xsaves::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xsaves_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::scaling::scale_by_2 << xsaves::scaling::from;
    this->expect_true(xsaves::scaling::get() == xsaves::scaling::scale_by_2);

    g_vmcs_fields[addr] = xsaves::scaling::scale_by_8 << xsaves::scaling::from;
    this->expect_true(xsaves::scaling::get_if_exists() == xsaves::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xsaves_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::address_size::_32bit << xsaves::address_size::from;
    this->expect_true(xsaves::address_size::get() == xsaves::address_size::_32bit);

    g_vmcs_fields[addr] = xsaves::address_size::_64bit << xsaves::address_size::from;
    this->expect_true(xsaves::address_size::get_if_exists() == xsaves::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xsaves_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::segment_register::cs << xsaves::segment_register::from;
    this->expect_true(xsaves::segment_register::get() == xsaves::segment_register::cs);

    g_vmcs_fields[addr] = xsaves::segment_register::gs << xsaves::segment_register::from;
    this->expect_true(xsaves::segment_register::get_if_exists() == xsaves::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xsaves_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::index_reg::rsi << xsaves::index_reg::from;
    this->expect_true(xsaves::index_reg::get() == xsaves::index_reg::rsi);

    g_vmcs_fields[addr] = xsaves::index_reg::r11 << xsaves::index_reg::from;
    this->expect_true(xsaves::index_reg::get_if_exists() == xsaves::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xsaves_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::index_reg_invalid::valid << xsaves::index_reg_invalid::from;
    this->expect_true(xsaves::index_reg_invalid::get() == xsaves::index_reg_invalid::valid);

    g_vmcs_fields[addr] = xsaves::index_reg_invalid::invalid << xsaves::index_reg_invalid::from;
    this->expect_true(xsaves::index_reg_invalid::get_if_exists() == xsaves::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xsaves_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::base_reg::rdi << xsaves::base_reg::from;
    this->expect_true(xsaves::base_reg::get() == xsaves::base_reg::rdi);

    g_vmcs_fields[addr] = xsaves::base_reg::rcx << xsaves::base_reg::from;
    this->expect_true(xsaves::base_reg::get_if_exists() == xsaves::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_xsaves_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = xsaves::base_reg_invalid::valid << xsaves::base_reg_invalid::from;
    this->expect_true(xsaves::base_reg_invalid::get() == xsaves::base_reg_invalid::valid);

    g_vmcs_fields[addr] = xsaves::base_reg_invalid::invalid << xsaves::base_reg_invalid::from;
    this->expect_true(xsaves::base_reg_invalid::get_if_exists() == xsaves::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(vmread::get_name() == vmread::name);
    this->expect_true(vmread::get() == 1UL);
    this->expect_true(vmread::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::scaling::scale_by_2 << vmread::scaling::from;
    this->expect_true(vmread::scaling::get() == vmread::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmread::scaling::scale_by_8 << vmread::scaling::from;
    this->expect_true(vmread::scaling::get_if_exists() == vmread::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread_reg1()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::reg1::rbp << vmread::reg1::from;
    this->expect_true(vmread::reg1::get() == vmread::reg1::rbp);

    g_vmcs_fields[addr] = vmread::reg1::r13 << vmread::reg1::from;
    this->expect_true(vmread::reg1::get_if_exists() == vmread::reg1::r13);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::address_size::_32bit << vmread::address_size::from;
    this->expect_true(vmread::address_size::get() == vmread::address_size::_32bit);

    g_vmcs_fields[addr] = vmread::address_size::_64bit << vmread::address_size::from;
    this->expect_true(vmread::address_size::get_if_exists() == vmread::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread_mem_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::mem_reg::mem << vmread::mem_reg::from;
    this->expect_true(vmread::mem_reg::get() == vmread::mem_reg::mem);

    g_vmcs_fields[addr] = vmread::mem_reg::reg << vmread::mem_reg::from;
    this->expect_true(vmread::mem_reg::get_if_exists() == vmread::mem_reg::reg);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::segment_register::cs << vmread::segment_register::from;
    this->expect_true(vmread::segment_register::get() == vmread::segment_register::cs);

    g_vmcs_fields[addr] = vmread::segment_register::gs << vmread::segment_register::from;
    this->expect_true(vmread::segment_register::get_if_exists() == vmread::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::index_reg::rsi << vmread::index_reg::from;
    this->expect_true(vmread::index_reg::get() == vmread::index_reg::rsi);

    g_vmcs_fields[addr] = vmread::index_reg::r11 << vmread::index_reg::from;
    this->expect_true(vmread::index_reg::get_if_exists() == vmread::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::index_reg_invalid::valid << vmread::index_reg_invalid::from;
    this->expect_true(vmread::index_reg_invalid::get() == vmread::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmread::index_reg_invalid::invalid << vmread::index_reg_invalid::from;
    this->expect_true(vmread::index_reg_invalid::get_if_exists() == vmread::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::base_reg::rdi << vmread::base_reg::from;
    this->expect_true(vmread::base_reg::get() == vmread::base_reg::rdi);

    g_vmcs_fields[addr] = vmread::base_reg::rcx << vmread::base_reg::from;
    this->expect_true(vmread::base_reg::get_if_exists() == vmread::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::base_reg_invalid::valid << vmread::base_reg_invalid::from;
    this->expect_true(vmread::base_reg_invalid::get() == vmread::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmread::base_reg_invalid::invalid << vmread::base_reg_invalid::from;
    this->expect_true(vmread::base_reg_invalid::get_if_exists() == vmread::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmread_reg2()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmread::reg2::rdx << vmread::reg2::from;
    this->expect_true(vmread::reg2::get() == vmread::reg2::rdx);

    g_vmcs_fields[addr] = vmread::reg2::rsp << vmread::reg2::from;
    this->expect_true(vmread::reg2::get_if_exists() == vmread::reg2::rsp);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = 1UL;

    this->expect_true(vmwrite::get_name() == vmwrite::name);
    this->expect_true(vmwrite::get() == 1UL);
    this->expect_true(vmwrite::get_if_exists() == 1UL);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite_scaling()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::scaling::scale_by_2 << vmwrite::scaling::from;
    this->expect_true(vmwrite::scaling::get() == vmwrite::scaling::scale_by_2);

    g_vmcs_fields[addr] = vmwrite::scaling::scale_by_8 << vmwrite::scaling::from;
    this->expect_true(vmwrite::scaling::get_if_exists() == vmwrite::scaling::scale_by_8);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite_reg1()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::reg1::rbp << vmwrite::reg1::from;
    this->expect_true(vmwrite::reg1::get() == vmwrite::reg1::rbp);

    g_vmcs_fields[addr] = vmwrite::reg1::r13 << vmwrite::reg1::from;
    this->expect_true(vmwrite::reg1::get_if_exists() == vmwrite::reg1::r13);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite_address_size()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::address_size::_32bit << vmwrite::address_size::from;
    this->expect_true(vmwrite::address_size::get() == vmwrite::address_size::_32bit);

    g_vmcs_fields[addr] = vmwrite::address_size::_64bit << vmwrite::address_size::from;
    this->expect_true(vmwrite::address_size::get_if_exists() == vmwrite::address_size::_64bit);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite_mem_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::mem_reg::mem << vmwrite::mem_reg::from;
    this->expect_true(vmwrite::mem_reg::get() == vmwrite::mem_reg::mem);

    g_vmcs_fields[addr] = vmwrite::mem_reg::reg << vmwrite::mem_reg::from;
    this->expect_true(vmwrite::mem_reg::get_if_exists() == vmwrite::mem_reg::reg);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite_segment_register()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::segment_register::cs << vmwrite::segment_register::from;
    this->expect_true(vmwrite::segment_register::get() == vmwrite::segment_register::cs);

    g_vmcs_fields[addr] = vmwrite::segment_register::gs << vmwrite::segment_register::from;
    this->expect_true(vmwrite::segment_register::get_if_exists() == vmwrite::segment_register::gs);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite_index_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::index_reg::rsi << vmwrite::index_reg::from;
    this->expect_true(vmwrite::index_reg::get() == vmwrite::index_reg::rsi);

    g_vmcs_fields[addr] = vmwrite::index_reg::r11 << vmwrite::index_reg::from;
    this->expect_true(vmwrite::index_reg::get_if_exists() == vmwrite::index_reg::r11);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite_index_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::index_reg_invalid::valid << vmwrite::index_reg_invalid::from;
    this->expect_true(vmwrite::index_reg_invalid::get() == vmwrite::index_reg_invalid::valid);

    g_vmcs_fields[addr] = vmwrite::index_reg_invalid::invalid << vmwrite::index_reg_invalid::from;
    this->expect_true(vmwrite::index_reg_invalid::get_if_exists() == vmwrite::index_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite_base_reg()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::base_reg::rdi << vmwrite::base_reg::from;
    this->expect_true(vmwrite::base_reg::get() == vmwrite::base_reg::rdi);

    g_vmcs_fields[addr] = vmwrite::base_reg::rcx << vmwrite::base_reg::from;
    this->expect_true(vmwrite::base_reg::get_if_exists() == vmwrite::base_reg::rcx);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite_base_reg_invalid()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::base_reg_invalid::valid << vmwrite::base_reg_invalid::from;
    this->expect_true(vmwrite::base_reg_invalid::get() == vmwrite::base_reg_invalid::valid);

    g_vmcs_fields[addr] = vmwrite::base_reg_invalid::invalid << vmwrite::base_reg_invalid::from;
    this->expect_true(vmwrite::base_reg_invalid::get_if_exists() == vmwrite::base_reg_invalid::invalid);
}

void
vmcs_ut::test_vmcs_vm_exit_instruction_information_vmwrite_reg2()
{
    using namespace vmcs::vm_exit_instruction_information;

    g_vmcs_fields[addr] = vmwrite::reg2::rdx << vmwrite::reg2::from;
    this->expect_true(vmwrite::reg2::get() == vmwrite::reg2::rdx);

    g_vmcs_fields[addr] = vmwrite::reg2::rsp << vmwrite::reg2::from;
    this->expect_true(vmwrite::reg2::get_if_exists() == vmwrite::reg2::rsp);
}

void
vmcs_ut::test_vmcs_exit_qualification()
{
    this->expect_true(vmcs::exit_qualification::exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    this->expect_true(vmcs::exit_qualification::get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    this->expect_true(vmcs::exit_qualification::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_debug_exception()
{
    this->expect_true(vmcs::exit_qualification::debug_exception::get_name() == "debug_exception"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    this->expect_true(vmcs::exit_qualification::debug_exception::get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    this->expect_true(vmcs::exit_qualification::debug_exception::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_debug_exception_b0()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 1UL;
    this->expect_true(vmcs::exit_qualification::debug_exception::b0::is_enabled());
    this->expect_false(vmcs::exit_qualification::debug_exception::b0::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    this->expect_false(vmcs::exit_qualification::debug_exception::b0::is_enabled_if_exists());
    this->expect_true(vmcs::exit_qualification::debug_exception::b0::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_debug_exception_b1()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 2UL;
    this->expect_true(vmcs::exit_qualification::debug_exception::b1::is_enabled());
    this->expect_false(vmcs::exit_qualification::debug_exception::b1::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    this->expect_false(vmcs::exit_qualification::debug_exception::b1::is_enabled_if_exists());
    this->expect_true(vmcs::exit_qualification::debug_exception::b1::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_debug_exception_b2()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 4UL;
    this->expect_true(vmcs::exit_qualification::debug_exception::b2::is_enabled());
    this->expect_false(vmcs::exit_qualification::debug_exception::b2::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    this->expect_false(vmcs::exit_qualification::debug_exception::b2::is_enabled_if_exists());
    this->expect_true(vmcs::exit_qualification::debug_exception::b2::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_debug_exception_b3()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 8UL;
    this->expect_true(vmcs::exit_qualification::debug_exception::b3::is_enabled());
    this->expect_false(vmcs::exit_qualification::debug_exception::b3::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    this->expect_false(vmcs::exit_qualification::debug_exception::b3::is_enabled_if_exists());
    this->expect_true(vmcs::exit_qualification::debug_exception::b3::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_debug_exception_reserved()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x600UL;
    this->expect_true(vmcs::exit_qualification::debug_exception::reserved::get() == 0x600U);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x602UL;
    this->expect_true(vmcs::exit_qualification::debug_exception::reserved::get_if_exists() == 0x600U);
}

void
vmcs_ut::test_vmcs_exit_qualification_debug_exception_bd()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2000UL;
    this->expect_true(vmcs::exit_qualification::debug_exception::bd::is_enabled());
    this->expect_false(vmcs::exit_qualification::debug_exception::bd::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    this->expect_false(vmcs::exit_qualification::debug_exception::bd::is_enabled_if_exists());
    this->expect_true(vmcs::exit_qualification::debug_exception::bd::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_debug_exception_bs()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x4000UL;
    this->expect_true(vmcs::exit_qualification::debug_exception::bs::is_enabled());
    this->expect_false(vmcs::exit_qualification::debug_exception::bs::is_disabled());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0UL;
    this->expect_false(vmcs::exit_qualification::debug_exception::bs::is_enabled_if_exists());
    this->expect_true(vmcs::exit_qualification::debug_exception::bs::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_page_fault_exception()
{
    this->expect_true(vmcs::exit_qualification::page_fault_exception::get_name() == "page_fault_exception"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x4000UL;
    this->expect_true(vmcs::exit_qualification::page_fault_exception::address() == 0x4000UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x10000000UL;
    this->expect_true(vmcs::exit_qualification::page_fault_exception::address_if_exists() == 0x10000000UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_sipi()
{
    this->expect_true(vmcs::exit_qualification::sipi::get_name() == "sipi"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x34UL;
    this->expect_true(vmcs::exit_qualification::sipi::get() == 0x34UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::sipi::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_sipi_vector()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xF34UL;
    this->expect_true(vmcs::exit_qualification::sipi::vector::get() == 0x34UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x3010UL;
    this->expect_true(vmcs::exit_qualification::sipi::vector::get_if_exists() == 0x10UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_task_switch()
{
    this->expect_true(vmcs::exit_qualification::task_switch::get_name() == "task_switch"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::task_switch::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::task_switch::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_task_switch_tss_selector()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xF0003456UL;
    this->expect_true(vmcs::exit_qualification::task_switch::tss_selector::get() == 0x3456UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::task_switch::tss_selector::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_task_switch_reserved()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFFF0000UL;
    this->expect_true(vmcs::exit_qualification::task_switch::reserved::get() == 0xFFF0000UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::task_switch::reserved::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_task_switch_source_of_task_switch_init()
{
    using namespace vmcs::exit_qualification::task_switch::source_of_task_switch_init;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(get() == call_instruction);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x40000000UL;
    this->expect_true(get() == iret_instruction);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x80000000UL;
    this->expect_true(get_if_exists() == jmp_instruction);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xC0000000UL;
    this->expect_true(get_if_exists() == task_gate_in_idt);
}

void
vmcs_ut::test_vmcs_exit_qualification_invept()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::invept::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::invept::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_invpcid()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::invpcid::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::invpcid::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_invvpid()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::invvpid::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::invvpid::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_lgdt()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::lgdt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::lgdt::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_lidt()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::lidt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::lidt::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_lldt()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::lldt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::lldt::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_ltr()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::ltr::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::ltr::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_sgdt()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::sgdt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::sgdt::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_sidt()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::sidt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::sidt::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_sldt()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::sldt::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::sldt::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_str()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::str::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::str::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_vmclear()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::vmclear::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::vmclear::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_vmptrld()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::vmptrld::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::vmptrld::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_vmread()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::vmread::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::vmread::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_vmwrite()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::vmwrite::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::vmwrite::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_vmxon()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::vmxon::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::vmxon::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_xrstors()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::xrstors::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::xrstors::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_xsaves()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::xsaves::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL;
    this->expect_true(vmcs::exit_qualification::xsaves::get_if_exists() == 0x2UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_control_register_access()
{
    this->expect_true(vmcs::exit_qualification::control_register_access::get_name() == "control_register_access"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x34UL;
    this->expect_true(vmcs::exit_qualification::control_register_access::get() == 0x34UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::control_register_access::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_control_register_access_control_register_number()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x42UL;
    this->expect_true(vmcs::exit_qualification::control_register_access::control_register_number::get() == 0x2UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::control_register_access::control_register_number::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_control_register_access_access_type()
{
    using namespace vmcs::exit_qualification::control_register_access::access_type;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x00UL;
    this->expect_true(get() == mov_to_cr);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x10UL;
    this->expect_true(get() == mov_from_cr);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x20UL;
    this->expect_true(get_if_exists() == clts);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x30UL;
    this->expect_true(get_if_exists() == lmsw);
}

void
vmcs_ut::test_vmcs_exit_qualification_control_register_access_lmsw_operand_type()
{
    using namespace vmcs::exit_qualification::control_register_access::lmsw_operand_type;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x00UL;
    this->expect_true(get() == reg);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x40UL;
    this->expect_true(get_if_exists() == mem);
}

void
vmcs_ut::test_vmcs_exit_qualification_control_register_access_reserved()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x3080UL;
    this->expect_true(vmcs::exit_qualification::control_register_access::reserved::get() == 0x3080UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::control_register_access::reserved::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_control_register_access_general_purpose_register()
{
    using namespace vmcs::exit_qualification::control_register_access::general_purpose_register;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x100UL;
    this->expect_true(get() == rcx);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xA00UL;
    this->expect_true(get_if_exists() == r10);
}

void
vmcs_ut::test_vmcs_exit_qualification_control_register_access_source_data()
{
    using namespace vmcs::exit_qualification::control_register_access::source_data;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x30000UL;
    this->expect_true(get() == 3UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x60000UL;
    this->expect_true(get_if_exists() == 6UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_mov_dr()
{
    this->expect_true(vmcs::exit_qualification::mov_dr::get_name() == "mov_dr"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x34UL;
    this->expect_true(vmcs::exit_qualification::mov_dr::get() == 0x34UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::mov_dr::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_mov_dr_debug_register_number()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x42UL;
    this->expect_true(vmcs::exit_qualification::mov_dr::debug_register_number::get() == 0x2UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::mov_dr::debug_register_number::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_mov_dr_reserved()
{
    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x88UL;
    this->expect_true(vmcs::exit_qualification::mov_dr::reserved::get() == 0x88UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::mov_dr::reserved::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_mov_dr_direction_of_access()
{
    using namespace vmcs::exit_qualification::mov_dr::direction_of_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x00UL;
    this->expect_true(get() == to_dr);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x10UL;
    this->expect_true(get_if_exists() == from_dr);
}

void
vmcs_ut::test_vmcs_exit_qualification_mov_dr_general_purpose_register()
{
    using namespace vmcs::exit_qualification::mov_dr::general_purpose_register;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x200UL;
    this->expect_true(get() == rdx);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xB00UL;
    this->expect_true(get_if_exists() == r11);
}

void
vmcs_ut::test_vmcs_exit_qualification_io_instruction()
{
    this->expect_true(vmcs::exit_qualification::io_instruction::get_name() == "io_instruction"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x34UL;
    this->expect_true(vmcs::exit_qualification::io_instruction::get() == 0x34UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::io_instruction::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_io_instruction_size_of_access()
{
    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(size_of_access::get() == size_of_access::one_byte);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(size_of_access::get() == size_of_access::two_byte);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x3UL;
    this->expect_true(size_of_access::get_if_exists() == size_of_access::four_byte);
}

void
vmcs_ut::test_vmcs_exit_qualification_io_instruction_direction_of_access()
{
    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(direction_of_access::get() == direction_of_access::out);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << direction_of_access::from;
    this->expect_true(direction_of_access::get_if_exists() == direction_of_access::in);
}

void
vmcs_ut::test_vmcs_exit_qualification_io_instruction_string_instruction()
{
    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(string_instruction::get() == string_instruction::not_string);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << string_instruction::from;
    this->expect_true(string_instruction::get_if_exists() == string_instruction::string);
}

void
vmcs_ut::test_vmcs_exit_qualification_io_instruction_rep_prefixed()
{
    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(rep_prefixed::get() == rep_prefixed::not_rep);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << rep_prefixed::from;
    this->expect_true(rep_prefixed::get_if_exists() == rep_prefixed::rep);
}

void
vmcs_ut::test_vmcs_exit_qualification_io_instruction_operand_encoding()
{
    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(operand_encoding::get() == operand_encoding::dx);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << operand_encoding::from;
    this->expect_true(operand_encoding::get_if_exists() == operand_encoding::immediate);
}

void
vmcs_ut::test_vmcs_exit_qualification_io_instruction_reserved()
{
    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(reserved::get() == 0x0UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xF80UL;
    this->expect_true(reserved::get_if_exists() == 0xF80UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_io_instruction_port_number()
{
    using namespace vmcs::exit_qualification::io_instruction;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(port_number::get() == 0x0UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << port_number::from;
    this->expect_true(port_number::get_if_exists() == 0x1UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_mwait()
{
    using namespace vmcs::exit_qualification::mwait;

    this->expect_true(get_name() == "mwait"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0U;
    this->expect_true(get() == 0U);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 1U;
    this->expect_true(get_if_exists() == 1U);
}

void
vmcs_ut::test_vmcs_exit_qualification_linear_apic_access()
{
    using namespace vmcs::exit_qualification::linear_apic_access;

    this->expect_true(get_name() == "linear_apic_access"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_linear_apic_access_offset()
{
    using namespace vmcs::exit_qualification::linear_apic_access;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(offset::get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(offset::get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_linear_apic_access_access_type()
{
    using namespace vmcs::exit_qualification::linear_apic_access::access_type;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(get() == read_during_instruction_execution);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << from;
    this->expect_true(get_if_exists() == write_during_instruction_execution);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x2UL << from;
    this->expect_true(get() == instruction_fetch);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x3UL << from;
    this->expect_true(get_if_exists() == event_delivery);
}

void
vmcs_ut::test_vmcs_exit_qualification_linear_apic_access_reserved()
{
    using namespace vmcs::exit_qualification::linear_apic_access::reserved;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(get() == 0U);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xF0000UL;
    this->expect_true(get_if_exists() == 0xF0000U);
}

void
vmcs_ut::test_vmcs_exit_qualification_guest_physical_apic_access()
{
    using namespace vmcs::exit_qualification::guest_physical_apic_access;

    this->expect_true(get_name() == "guest_physical_apic_access"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(get() == 0x1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(get_if_exists() == 0x0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_guest_physical_apic_access_access_type()
{
    using namespace vmcs::exit_qualification::guest_physical_apic_access::access_type;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xAUL << from;
    this->expect_true(get_if_exists() == event_delivery);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xFUL << from;
    this->expect_true(get() == instruction_fetch_or_execution);
}

void
vmcs_ut::test_vmcs_exit_qualification_guest_physical_apic_access_reserved()
{
    using namespace vmcs::exit_qualification::guest_physical_apic_access::reserved;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(get() == 0U);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0xF0000UL;
    this->expect_true(get_if_exists() == 0xF0000U);
}

void
vmcs_ut::test_vmcs_exit_qualification_ept_violation()
{
    this->expect_true(vmcs::exit_qualification::ept_violation::get_name() == "ept_violation"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::ept_violation::get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::ept_violation::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_ept_violation_data_read()
{
    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(data_read::is_enabled());
    this->expect_true(data_read::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(data_read::is_disabled());
    this->expect_true(data_read::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_ept_violation_data_write()
{
    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << data_write::from;
    this->expect_true(data_write::is_enabled());
    this->expect_true(data_write::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << data_write::from;
    this->expect_true(data_write::is_disabled());
    this->expect_true(data_write::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_ept_violation_instruction_fetch()
{
    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << instruction_fetch::from;
    this->expect_true(instruction_fetch::is_enabled());
    this->expect_true(instruction_fetch::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << instruction_fetch::from;
    this->expect_true(instruction_fetch::is_disabled());
    this->expect_true(instruction_fetch::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_ept_violation_readable()
{
    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << readable::from;
    this->expect_true(readable::is_enabled());
    this->expect_true(readable::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << readable::from;
    this->expect_true(readable::is_disabled());
    this->expect_true(readable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_ept_violation_writeable()
{
    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << writeable::from;
    this->expect_true(writeable::is_enabled());
    this->expect_true(writeable::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << writeable::from;
    this->expect_true(writeable::is_disabled());
    this->expect_true(writeable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_ept_violation_executable()
{
    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << executable::from;
    this->expect_true(executable::is_enabled());
    this->expect_true(executable::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << executable::from;
    this->expect_true(executable::is_disabled());
    this->expect_true(executable::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_ept_violation_reserved()
{
    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x40UL;
    this->expect_true(reserved::get() == 0x40UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(reserved::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_ept_violation_valid_guest_linear_address()
{
    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << valid_guest_linear_address::from;
    this->expect_true(valid_guest_linear_address::is_enabled());
    this->expect_true(valid_guest_linear_address::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << valid_guest_linear_address::from;
    this->expect_true(valid_guest_linear_address::is_disabled());
    this->expect_true(valid_guest_linear_address::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_ept_violation_nmi_unblocking_due_to_iret()
{
    using namespace vmcs::exit_qualification::ept_violation;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL << nmi_unblocking_due_to_iret::from;
    this->expect_true(nmi_unblocking_due_to_iret::is_enabled());
    this->expect_true(nmi_unblocking_due_to_iret::is_enabled_if_exists());

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL << nmi_unblocking_due_to_iret::from;
    this->expect_true(nmi_unblocking_due_to_iret::is_disabled());
    this->expect_true(nmi_unblocking_due_to_iret::is_disabled_if_exists());
}

void
vmcs_ut::test_vmcs_exit_qualification_eoi_virtualization()
{
    this->expect_true(vmcs::exit_qualification::eoi_virtualization::get_name() == "eoi_virtualization"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::eoi_virtualization::get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::eoi_virtualization::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_eoi_virtualization_vector()
{
    using namespace vmcs::exit_qualification::eoi_virtualization::vector;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_apic_write()
{
    this->expect_true(vmcs::exit_qualification::apic_write::get_name() == "apic_write"_s);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(vmcs::exit_qualification::apic_write::get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(vmcs::exit_qualification::apic_write::get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_exit_qualification_apic_write_offset()
{
    using namespace vmcs::exit_qualification::apic_write::offset;

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x1UL;
    this->expect_true(get() == 1UL);

    g_vmcs_fields[vmcs::exit_qualification::addr] = 0x0UL;
    this->expect_true(get_if_exists() == 0UL);
}

void
vmcs_ut::test_vmcs_io_rcx()
{
    g_vmcs_fields[vmcs::io_rcx::addr] = 1U;
    this->expect_true(vmcs::io_rcx::get() == 1U);

    g_vmcs_fields[vmcs::io_rcx::addr] = 0U;
    this->expect_true(vmcs::io_rcx::get_if_exists() == 0U);
}

void
vmcs_ut::test_vmcs_io_rsi()
{
    g_vmcs_fields[vmcs::io_rsi::addr] = 1U;
    this->expect_true(vmcs::io_rsi::get() == 1U);

    g_vmcs_fields[vmcs::io_rsi::addr] = 0U;
    this->expect_true(vmcs::io_rsi::get_if_exists() == 0U);
}

void
vmcs_ut::test_vmcs_io_rdi()
{
    g_vmcs_fields[vmcs::io_rdi::addr] = 1U;
    this->expect_true(vmcs::io_rdi::get() == 1U);

    g_vmcs_fields[vmcs::io_rdi::addr] = 0U;
    this->expect_true(vmcs::io_rdi::get_if_exists() == 0U);
}

void
vmcs_ut::test_vmcs_io_rip()
{
    g_vmcs_fields[vmcs::io_rip::addr] = 1U;
    this->expect_true(vmcs::io_rip::get() == 1U);

    g_vmcs_fields[vmcs::io_rip::addr] = 0U;
    this->expect_true(vmcs::io_rip::get_if_exists() == 0U);
}

void
vmcs_ut::test_vmcs_guest_linear_address()
{
    g_vmcs_fields[vmcs::guest_linear_address::addr] = 1U;
    this->expect_true(vmcs::guest_linear_address::get() == 1U);

    g_vmcs_fields[vmcs::guest_linear_address::addr] = 0U;
    this->expect_true(vmcs::guest_linear_address::get_if_exists() == 0U);
}
