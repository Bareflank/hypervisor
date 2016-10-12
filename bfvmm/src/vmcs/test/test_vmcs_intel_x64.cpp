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
#include <vmcs/vmcs_intel_x64_resume.h>
#include <vmcs/vmcs_intel_x64_promote.h>

using namespace intel_x64;

extern size_t g_new_throws_bad_alloc;
extern bool g_vmread_fails;
extern bool g_vmwrite_fails;

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
setup_vmcs_host_control_registers_and_msrs()
{
    g_vmcs_fields[vmcs::host_cr0::addr] = 0xffffFFFFffffFFFF;
    g_vmcs_fields[vmcs::host_cr3::addr] = 0x0000000010000000;
    g_vmcs_fields[vmcs::host_cr4::addr] = 0xffffFFFFffffFFFF;
    g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_ESP] = 0x0000000010000000;
    g_vmcs_fields[VMCS_HOST_IA32_SYSENTER_EIP] = 0x0000000010000000;
    g_vmcs_fields[VMCS_HOST_IA32_PERF_GLOBAL_CTRL_FULL] = 0x0;
    g_vmcs_fields[VMCS_HOST_IA32_PAT_FULL] = 0x0;
    g_vmcs_fields[VMCS_HOST_IA32_EFER_FULL] = IA32_EFER_LME | IA32_EFER_LMA;
    g_vmcs_fields[VMCS_HOST_RIP] = 0x0000000010000000;
}

static void
setup_vmcs_host_segment_and_descriptor_table_registers()
{
    g_vmcs_fields[VMCS_HOST_FS_BASE] = 0x0000000010000000;
    g_vmcs_fields[VMCS_HOST_GS_BASE] = 0x0000000010000000;
    g_vmcs_fields[VMCS_HOST_GDTR_BASE] = 0x0000000010000000;
    g_vmcs_fields[VMCS_HOST_IDTR_BASE] = 0x0000000010000000;
    g_vmcs_fields[VMCS_HOST_TR_BASE] = 0x0000000010000000;
}

static void
setup_vmcs_host_fields()
{
    setup_vmcs_host_control_registers_and_msrs();
    setup_vmcs_host_segment_and_descriptor_table_registers();
}

static void
setup_vmcs_guest_control_and_debug_fields()
{
    g_vmcs_fields[vmcs::guest_cr0::addr] = 0xffffFFFFffffFFFF;
    g_vmcs_fields[vmcs::guest_cr3::addr] = 0x0000000000001000;
    g_vmcs_fields[vmcs::guest_cr4::addr] = 0xffffFFFFfffdFFFF;
    g_vmcs_fields[VMCS_GUEST_DR7] = 0x00000000ffffFFFF;
    g_vmcs_fields[VMCS_GUEST_IA32_SYSENTER_ESP] = 0x0000000010000000;
    g_vmcs_fields[VMCS_GUEST_IA32_SYSENTER_EIP] = 0x0000000010000000;
    g_vmcs_fields[VMCS_GUEST_IA32_PERF_GLOBAL_CTRL_FULL] = 0x0;
    g_vmcs_fields[VMCS_GUEST_IA32_PAT_FULL] = 0x0;
    g_vmcs_fields[VMCS_GUEST_IA32_EFER_FULL] = IA32_EFER_LME | IA32_EFER_LMA;
    g_vmcs_fields[VMCS_GUEST_IA32_DEBUGCTL_FULL] = 0x0;
}

static void
setup_vmcs_guest_segment_registers()
{
    g_vmcs_fields[VMCS_GUEST_CS_ACCESS_RIGHTS] = 0x9 | SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR | SEGMENT_ACCESS_RIGHTS_PRESENT | SEGMENT_ACCESS_RIGHTS_DPL;
    g_vmcs_fields[VMCS_GUEST_SS_ACCESS_RIGHTS] = 0x3 | SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR | SEGMENT_ACCESS_RIGHTS_PRESENT | SEGMENT_ACCESS_RIGHTS_DPL;
    g_vmcs_fields[VMCS_GUEST_DS_ACCESS_RIGHTS] = 0x3 | SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR | SEGMENT_ACCESS_RIGHTS_PRESENT;
    g_vmcs_fields[VMCS_GUEST_ES_ACCESS_RIGHTS] = 0x3 | SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR | SEGMENT_ACCESS_RIGHTS_PRESENT;
    g_vmcs_fields[VMCS_GUEST_FS_ACCESS_RIGHTS] = 0x3 | SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR | SEGMENT_ACCESS_RIGHTS_PRESENT;
    g_vmcs_fields[VMCS_GUEST_GS_ACCESS_RIGHTS] = 0x3 | SEGMENT_ACCESS_RIGHTS_SYSTEM_DESCRIPTOR | SEGMENT_ACCESS_RIGHTS_PRESENT;
    g_vmcs_fields[VMCS_GUEST_TR_ACCESS_RIGHTS] = 0xb | SEGMENT_ACCESS_RIGHTS_PRESENT;
    g_vmcs_fields[VMCS_GUEST_LDTR_ACCESS_RIGHTS] = 0x2 | SEGMENT_ACCESS_RIGHTS_PRESENT;

    g_vmcs_fields[VMCS_GUEST_CS_LIMIT] = 0x00000100;
    g_vmcs_fields[VMCS_GUEST_SS_LIMIT] = 0x00000100;
    g_vmcs_fields[VMCS_GUEST_DS_LIMIT] = 0x00000100;
    g_vmcs_fields[VMCS_GUEST_ES_LIMIT] = 0x00000100;
    g_vmcs_fields[VMCS_GUEST_FS_LIMIT] = 0x00000100;
    g_vmcs_fields[VMCS_GUEST_TR_LIMIT] = 0x00000100;
    g_vmcs_fields[VMCS_GUEST_LDTR_LIMIT] = 0x00000100;
}

static void
setup_vmcs_guest_descriptor_table_registers()
{
    g_vmcs_fields[VMCS_GUEST_GDTR_LIMIT] = 0x00000100;
    g_vmcs_fields[VMCS_GUEST_IDTR_LIMIT] = 0x00000100;
    g_vmcs_fields[VMCS_GUEST_GDTR_BASE] = 0x0000000010000000;
    g_vmcs_fields[VMCS_GUEST_IDTR_BASE] = 0x0000000010000000;
}

static void
setup_vmcs_guest_rip_and_rflags()
{
    g_vmcs_fields[VMCS_GUEST_RIP] = 0x0000000000ff0000;
    g_vmcs_fields[vmcs::guest_rflags::addr] = rflags::always_enabled::mask | rflags::interrupt_enable_flag::mask;
    g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = VM_INTERRUPT_INFORMATION_VALID;
}

static void
setup_vmcs_guest_non_register_state()
{
    g_vmcs_fields[VMCS_GUEST_ACTIVITY_STATE] = 0x0;
    g_vmcs_fields[VMCS_GUEST_INTERRUPTIBILITY_STATE] = VM_INTERRUPTABILITY_STATE_SMI;
    g_vmcs_fields[VMCS_VMCS_LINK_POINTER_FULL] = 0xffffFFFFffffFFFF;

}

static void
setup_vmcs_guest_fields()
{
    setup_vmcs_guest_control_and_debug_fields();
    setup_vmcs_guest_segment_registers();
    setup_vmcs_guest_descriptor_table_registers();
    setup_vmcs_guest_rip_and_rflags();
    setup_vmcs_guest_non_register_state();
}

void
setup_vm_execution_control_fields()
{
    g_vmcs_fields[VMCS_PIN_BASED_VM_EXECUTION_CONTROLS] = 0xffffFFFFffffFF7F;
    g_vmcs_fields[VMCS_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS] = 0xffffFFFFffffFFFF;
    g_vmcs_fields[VMCS_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS] = 0xffffFFFFffffFdee;
    g_vmcs_fields[VMCS_CR3_TARGET_COUNT] = 3;
    g_vmcs_fields[VMCS_ADDRESS_OF_IO_BITMAP_A_FULL] = 0x0000000000000000;
    g_vmcs_fields[VMCS_ADDRESS_OF_IO_BITMAP_B_FULL] = 0x0000000000000000;
    g_vmcs_fields[VMCS_ADDRESS_OF_MSR_BITMAPS_FULL] = 0x0000000000000000;
    g_vmcs_fields[VMCS_VIRTUAL_APIC_ADDRESS_FULL] = 0x0000000000001000;
    g_vmcs_fields[VMCS_TPR_THRESHOLD] = 0x0000000F00000000;
    g_vmcs_fields[VMCS_APIC_ACCESS_ADDRESS_FULL] = 0x0000000010000000;
    g_vmcs_fields[vmcs::posted_interrupt_notification_vector::addr] = 0x0000000000000000;
    g_vmcs_fields[VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL] = 0x0000000010000000;
    g_vmcs_fields[vmcs::virtual_processor_identifier::addr] = 0x0000000000000002;
    g_vmcs_fields[VMCS_EPT_POINTER_FULL] = 0x000000000000001e;
    g_vmcs_fields[VMCS_PML_ADDRESS_FULL] = 0x0000000000000000;
    g_vmcs_fields[VMCS_VM_FUNCTION_CONTROLS_FULL] = 0xffffFFFFffffFFFF;
    g_vmcs_fields[VMCS_EPTP_LIST_ADDRESS_FULL] = 0x0000000010000000;
    g_vmcs_fields[VMCS_VMREAD_BITMAP_ADDRESS_FULL] = 0x0000000010000000;
    g_vmcs_fields[VMCS_VMWRITE_BITMAP_ADDRESS_FULL] = 0x0000000010000000;
    g_vmcs_fields[VMCS_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS_FULL] = 0x0000000010000000;
}

void
setup_vm_exit_control_fields()
{
    g_vmcs_fields[VMCS_VM_EXIT_CONTROLS] = 0xffffFFFFffffFFFF;
    g_vmcs_fields[VMCS_VM_EXIT_MSR_STORE_COUNT] = 0xff0000;
    g_vmcs_fields[VMCS_VM_EXIT_MSR_STORE_ADDRESS_FULL] = 0x1000;
    g_vmcs_fields[VMCS_VM_EXIT_MSR_LOAD_COUNT] = 0xff0000;
    g_vmcs_fields[VMCS_VM_EXIT_MSR_LOAD_ADDRESS_FULL] = 0x1000;
}

void
setup_vm_entry_control_fields()
{
    g_vmcs_fields[VMCS_VM_ENTRY_CONTROLS] = 0xffffFFFFffffFFFF;
    g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] = VM_INTERRUPT_INFORMATION_VALID;
    g_vmcs_fields[VMCS_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD] |= VM_INTERRUPT_INFORMATION_DELIVERY_ERROR | 0x308;
    g_vmcs_fields[vmcs::guest_cr0::addr] = cr0::protection_enable::mask;
    g_vmcs_fields[VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE] = 0x0;
    g_vmcs_fields[VMCS_VM_ENTRY_MSR_LOAD_COUNT] = 0xff0000;
    g_vmcs_fields[VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL] = 0x0000000010000000;
}

void
setup_msrs()
{
    g_msrs[msrs::ia32_vmx_basic::addr] = 0x7ffFFFF;
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffFFFF01010101;
    g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffFFFF01010101;
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffFdeefffffdee;
    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = 0x0000000000000000;
    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] |= msrs::ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::mask;
    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] |= msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::mask;
    g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] |= msrs::ia32_vmx_ept_vpid_cap::accessed_dirty_support::mask;
    g_msrs[msrs::ia32_vmx_vmfunc::addr] = 0xffffFFFFffffFFFF;
    g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffFFFF01010101;
    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffFFFF01010101;

    g_msrs[msrs::ia32_vmx_cr0_fixed0::addr] = 0x0;
    g_msrs[msrs::ia32_vmx_cr0_fixed1::addr] = 0xffffFFFFffffFFFF;
    g_msrs[msrs::ia32_vmx_cr4_fixed0::addr] = 0x0;
    g_msrs[msrs::ia32_vmx_cr4_fixed1::addr] = 0xffffFFFFffffFFFF;

    g_msrs[IA32_EFER_MSR] = IA32_EFER_LMA;
}

static void
setup_vmcs_fields()
{
    setup_vm_execution_control_fields();
    setup_vm_exit_control_fields();
    setup_vm_entry_control_fields();
    setup_vmcs_guest_fields();
    setup_vmcs_host_fields();
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
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr_limit).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr_limit).Return(0);

    mocks.OnCall(state_in, vmcs_intel_x64_state::es_access_rights).Return(0x10000);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs_access_rights).Return(0x10000);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss_access_rights).Return(0x10000);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_access_rights).Return(0x10000);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_access_rights).Return(0x10000);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs_access_rights).Return(0x10000);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs_access_rights).Return(0x10000);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr_access_rights).Return(0x10000);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr_access_rights).Return(0x10000);

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

    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_debugctl_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_pat_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_efer_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_perf_global_ctrl_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_cs_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_esp_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_eip_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_fs_base_msr).Return(0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_gs_base_msr).Return(0);

    mocks.OnCall(state_in, vmcs_intel_x64_state::dump);
}

static void
setup_vmcs_launch_failure(MockRepository &mocks, intrinsics_intel_x64 *in)
{
    setup_msrs();
    setup_vmcs_fields();

    Call &vmlaunch = mocks.OnCall(in, intrinsics_intel_x64::vmlaunch).Return(false);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).After(vmlaunch).Do(__read_msr);
    mocks.OnCall(in, intrinsics_intel_x64::vmread).After(vmlaunch).Do(__vmread);
}

static void
setup_vmcs_intrinsics(MockRepository &mocks, memory_manager *mm, intrinsics_intel_x64 *in)
{
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);
    mocks.OnCall(mm, memory_manager::physint_to_virtptr).Do(physint_to_virtptr);

    mocks.OnCall(in, intrinsics_intel_x64::read_msr).Do(__read_msr);
    mocks.OnCall(in, intrinsics_intel_x64::cpuid_eax).Do(cpuid_eax);

    mocks.OnCall(in, intrinsics_intel_x64::vmclear).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmptrld).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmlaunch).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmwrite).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmread).Return(true);
}

void
vmcs_ut::test_launch_success()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm, in.get());
    setup_vmcs_x64_state_intrinsics(mocks, host_state.get());
    setup_vmcs_x64_state_intrinsics(mocks, guest_state.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);

        this->expect_no_exception([&] { vmcs.launch(host_state, guest_state); });
    });
}

void
vmcs_ut::test_constructor_null_intrinsics()
{
    this->expect_no_exception([&] { vmcs_intel_x64(nullptr); });
}

void
vmcs_ut::test_launch_vmlaunch_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm, in.get());
    setup_vmcs_x64_state_intrinsics(mocks, host_state.get());
    setup_vmcs_x64_state_intrinsics(mocks, guest_state.get());
    setup_vmcs_launch_failure(mocks, in.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);

        auto e = std::make_shared<std::runtime_error>("vmcs launch failed");
        this->expect_exception([&] { vmcs.launch(host_state, guest_state); }, e);
    });
}

void
vmcs_ut::test_launch_create_vmcs_region_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm, in.get());
    setup_vmcs_x64_state_intrinsics(mocks, host_state.get());
    setup_vmcs_x64_state_intrinsics(mocks, guest_state.get());

    auto ___ = gsl::finally([&]
    { g_virt_to_phys_return_nullptr = false; });

    g_virt_to_phys_return_nullptr = true;

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);

        auto e = std::make_shared<std::logic_error>("m_vmcs_region_phys == nullptr");
        this->expect_exception([&] { vmcs.launch(host_state, guest_state); }, e);
    });
}

void
vmcs_ut::test_launch_create_exit_handler_stack_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm, in.get());

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);

        auto ___ = gsl::finally([&]
        { g_new_throws_bad_alloc = 0; });

        g_new_throws_bad_alloc = STACK_SIZE * 2;

        auto e = std::make_shared<std::bad_alloc>();
        this->expect_exception([&] { vmcs.launch(host_state, guest_state); }, e);
    });
}

void
vmcs_ut::test_launch_clear_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm, in.get());
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmclear).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);

        auto e = std::make_shared<std::runtime_error>("vmcs clear failed");
        this->expect_exception([&] { vmcs.launch(host_state, guest_state); }, e);
    });
}

void
vmcs_ut::test_launch_load_failure()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager>();
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);
    auto host_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);
    auto guest_state = bfn::mock_shared<vmcs_intel_x64_state>(mocks);

    setup_vmcs_intrinsics(mocks, mm, in.get());
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmptrld).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);

        auto e = std::make_shared<std::runtime_error>("vmcs load failed");
        this->expect_exception([&] { vmcs.launch(host_state, guest_state); }, e);
    });
}

void
vmcs_ut::test_promote_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCallFunc(vmcs_promote).Do(vmcs_promote_fail);
    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Return(true);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);

        auto e = std::make_shared<std::runtime_error>("vmcs promote failed");
        this->expect_exception([&] { vmcs.promote(); }, e);
    });
}

void
vmcs_ut::test_resume_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCallFunc(vmcs_resume).Do(vmcs_resume_fail);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);

        auto e = std::make_shared<std::runtime_error>("vmcs resume failed");
        this->expect_exception([&] { vmcs.resume(); }, e);
    });
}

void
vmcs_ut::test_vmread_failure()
{
    g_vmread_fails = true;

    auto ___ = gsl::finally([&]
    { g_vmread_fails = false; });

    auto e = std::make_shared<std::runtime_error>("vmread failed");
    this->expect_exception([&] { vmcs::virtual_processor_identifier::get(); }, e);
}

void
vmcs_ut::test_vmwrite_failure()
{
    g_vmwrite_fails = true;

    auto ___ = gsl::finally([&]
    { g_vmwrite_fails = false; });

    auto e = std::make_shared<std::runtime_error>("vmwrite failed");
    this->expect_exception([&] { vmcs::virtual_processor_identifier::set(100UL); }, e);
}

void
vmcs_ut::test_vmcs_virtual_processor_identifier()
{
    vmcs::virtual_processor_identifier::set(100UL);
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::enable_vpid::mask;

    this->expect_true(vmcs::virtual_processor_identifier::get() == 100UL);
    this->expect_true(vmcs::virtual_processor_identifier::is_supported());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;

    this->expect_false(vmcs::virtual_processor_identifier::is_supported());
}

void
vmcs_ut::test_vmcs_posted_interrupt_notification_vector()
{
    vmcs::posted_interrupt_notification_vector::set(100UL);
    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask;

    this->expect_true(vmcs::posted_interrupt_notification_vector::get() == 100UL);
    this->expect_true(vmcs::posted_interrupt_notification_vector::is_supported());

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0x0;

    this->expect_false(vmcs::posted_interrupt_notification_vector::is_supported());
}

void
vmcs_ut::test_vmcs_eptp_index()
{
    vmcs::eptp_index::set(100UL);
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::ept_violation_ve::mask;

    this->expect_true(vmcs::eptp_index::get() == 100UL);
    this->expect_true(vmcs::eptp_index::is_supported());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;

    this->expect_false(vmcs::eptp_index::is_supported());
}

void
vmcs_ut::test_vmcs_guest_es_selector()
{
    vmcs::guest_es_selector::set(100UL);

    this->expect_true(vmcs::guest_es_selector::get() == 100UL);
    this->expect_true(vmcs::guest_es_selector::is_supported());
}

void
vmcs_ut::test_vmcs_guest_cs_selector()
{
    vmcs::guest_cs_selector::set(100UL);

    this->expect_true(vmcs::guest_cs_selector::get() == 100UL);
    this->expect_true(vmcs::guest_cs_selector::is_supported());
}

void
vmcs_ut::test_vmcs_guest_ss_selector()
{
    vmcs::guest_ss_selector::set(100UL);

    this->expect_true(vmcs::guest_ss_selector::get() == 100UL);
    this->expect_true(vmcs::guest_ss_selector::is_supported());
}

void
vmcs_ut::test_vmcs_guest_ds_selector()
{
    vmcs::guest_ds_selector::set(100UL);

    this->expect_true(vmcs::guest_ds_selector::get() == 100UL);
    this->expect_true(vmcs::guest_ds_selector::is_supported());
}

void
vmcs_ut::test_vmcs_guest_fs_selector()
{
    vmcs::guest_fs_selector::set(100UL);

    this->expect_true(vmcs::guest_fs_selector::get() == 100UL);
    this->expect_true(vmcs::guest_fs_selector::is_supported());
}

void
vmcs_ut::test_vmcs_guest_gs_selector()
{
    vmcs::guest_gs_selector::set(100UL);

    this->expect_true(vmcs::guest_gs_selector::get() == 100UL);
    this->expect_true(vmcs::guest_gs_selector::is_supported());
}

void
vmcs_ut::test_vmcs_guest_ldtr_selector()
{
    vmcs::guest_ldtr_selector::set(100UL);

    this->expect_true(vmcs::guest_ldtr_selector::get() == 100UL);
    this->expect_true(vmcs::guest_ldtr_selector::is_supported());
}

void
vmcs_ut::test_vmcs_guest_tr_selector()
{
    vmcs::guest_tr_selector::set(100UL);

    this->expect_true(vmcs::guest_tr_selector::get() == 100UL);
    this->expect_true(vmcs::guest_tr_selector::is_supported());
}

void
vmcs_ut::test_vmcs_guest_interrupt_status()
{
    vmcs::guest_interrupt_status::set(100UL);
    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = msrs::ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask;

    this->expect_true(vmcs::guest_interrupt_status::get() == 100UL);
    this->expect_true(vmcs::guest_interrupt_status::is_supported());

    g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0x0;

    this->expect_false(vmcs::guest_interrupt_status::is_supported());
}

void
vmcs_ut::test_vmcs_host_es_selector()
{
    vmcs::host_es_selector::set(100UL);

    this->expect_true(vmcs::host_es_selector::get() == 100UL);
    this->expect_true(vmcs::host_es_selector::is_supported());
}

void
vmcs_ut::test_vmcs_host_cs_selector()
{
    vmcs::host_cs_selector::set(100UL);

    this->expect_true(vmcs::host_cs_selector::get() == 100UL);
    this->expect_true(vmcs::host_cs_selector::is_supported());
}

void
vmcs_ut::test_vmcs_host_ss_selector()
{
    vmcs::host_ss_selector::set(100UL);

    this->expect_true(vmcs::host_ss_selector::get() == 100UL);
    this->expect_true(vmcs::host_ss_selector::is_supported());
}

void
vmcs_ut::test_vmcs_host_ds_selector()
{
    vmcs::host_ds_selector::set(100UL);

    this->expect_true(vmcs::host_ds_selector::get() == 100UL);
    this->expect_true(vmcs::host_ds_selector::is_supported());
}

void
vmcs_ut::test_vmcs_host_fs_selector()
{
    vmcs::host_fs_selector::set(100UL);

    this->expect_true(vmcs::host_fs_selector::get() == 100UL);
    this->expect_true(vmcs::host_fs_selector::is_supported());
}

void
vmcs_ut::test_vmcs_host_gs_selector()
{
    vmcs::host_gs_selector::set(100UL);

    this->expect_true(vmcs::host_gs_selector::get() == 100UL);
    this->expect_true(vmcs::host_gs_selector::is_supported());
}

void
vmcs_ut::test_vmcs_host_tr_selector()
{
    vmcs::host_tr_selector::set(100UL);

    this->expect_true(vmcs::host_tr_selector::get() == 100UL);
    this->expect_true(vmcs::host_tr_selector::is_supported());
}

void
vmcs_ut::test_vmcs_guest_rflags()
{
    vmcs::guest_rflags::set(100UL);

    this->expect_true(vmcs::guest_rflags::get() == 100UL);
    this->expect_true(vmcs::guest_rflags::is_supported());
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
    vmcs::guest_rflags::always_enabled::set(1UL);
    this->expect_true(vmcs::guest_rflags::always_enabled::get() == 1UL);

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
