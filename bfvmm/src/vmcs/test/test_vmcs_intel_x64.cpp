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
#include <vmcs/vmcs_intel_x64_promote.h>
#include <vmcs/vmcs_intel_x64_resume.h>

extern size_t g_new_throws_bad_alloc;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;
uint8_t span[0x81] = {0};
bool g_virt_to_phys_return_nullptr = false;
bool g_phys_to_virt_return_nullptr = false;

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

uint64_t
read_msr(uint32_t msr)
{
    return g_msrs[msr];
}

bool
vmread(uint64_t field, uint64_t *val)
{
    *val = g_vmcs_fields[field];
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

static uint16_t es() { return 0; }
static uint16_t cs() { return 0; }
static uint16_t ss() { return 0; }
static uint16_t ds() { return 0; }
static uint16_t fs() { return 0; }
static uint16_t gs() { return 0; }
static uint16_t ldtr() { return 0; }
static uint16_t tr() { return 0; }

static uint64_t cr0() { return 0; }
static uint64_t cr3() { return 0; }
static uint64_t cr4() { return 0; }
static uint64_t dr7() { return 0; }

static uint64_t rflags() { return 0; }

static uint64_t gdt_base() { return 0; }
static uint64_t idt_base() { return 0; }

static uint16_t gdt_limit() { return 0; }
static uint16_t idt_limit() { return 0; }

static uint32_t es_limit() { return 0; }
static uint32_t cs_limit() { return 0; }
static uint32_t ss_limit() { return 0; }
static uint32_t ds_limit() { return 0; }
static uint32_t fs_limit() { return 0; }
static uint32_t gs_limit() { return 0; }
static uint32_t ldtr_limit() { return 0; }
static uint32_t tr_limit() { return 0; }

static uint32_t es_access_rights() { return 0x10000; }
static uint32_t cs_access_rights() { return 0x10000; }
static uint32_t ss_access_rights() { return 0x10000; }
static uint32_t ds_access_rights() { return 0x10000; }
static uint32_t fs_access_rights() { return 0x10000; }
static uint32_t gs_access_rights() { return 0x10000; }
static uint32_t ldtr_access_rights() { return 0x10000; }
static uint32_t tr_access_rights() { return 0x10000; }

static uint64_t es_base() { return 0; }
static uint64_t cs_base() { return 0; }
static uint64_t ss_base() { return 0; }
static uint64_t ds_base() { return 0; }
static uint64_t fs_base() { return 0; }
static uint64_t gs_base() { return 0; }
static uint64_t ldtr_base() { return 0; }
static uint64_t tr_base() { return 0; }

static uint64_t ia32_debugctl_msr() { return 0; }
static uint64_t ia32_pat_msr() { return 0; }
static uint64_t ia32_efer_msr() { return 0; }
static uint64_t ia32_perf_global_ctrl_msr() { return 0; }
static uint64_t ia32_sysenter_cs_msr() { return 0; }
static uint64_t ia32_sysenter_esp_msr() { return 0; }
static uint64_t ia32_sysenter_eip_msr() { return 0; }
static uint64_t ia32_fs_base_msr() { return 0; }
static uint64_t ia32_gs_base_msr() { return 0; }

static uintptr_t
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

void
setup_mock(MockRepository &mocks, memory_manager *mm, intrinsics_intel_x64 *in)
{
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).Do(read_msr);
    mocks.OnCall(in, intrinsics_intel_x64::vmread).Do(vmread);
    mocks.OnCall(in, intrinsics_intel_x64::cpuid_eax).With(0x80000008).Return(32);
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::physint_to_virtptr).Do(physint_to_virtptr);
}

static void
setup_vmcs_host_control_registers_and_msrs()
{
    g_vmcs_fields[VMCS_HOST_CR0] = 0xffffFFFFffffFFFF;
    g_vmcs_fields[VMCS_HOST_CR3] = 0x0000000010000000;
    g_vmcs_fields[VMCS_HOST_CR4] = 0xffffFFFFffffFFFF;
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
    g_vmcs_fields[VMCS_HOST_ES_SELECTOR] = ~(SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG);
    g_vmcs_fields[VMCS_HOST_CS_SELECTOR] = ~(SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG);
    g_vmcs_fields[VMCS_HOST_SS_SELECTOR] = ~(SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG);
    g_vmcs_fields[VMCS_HOST_DS_SELECTOR] = ~(SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG);
    g_vmcs_fields[VMCS_HOST_FS_SELECTOR] = ~(SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG);
    g_vmcs_fields[VMCS_HOST_GS_SELECTOR] = ~(SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG);
    g_vmcs_fields[VMCS_HOST_TR_SELECTOR] = ~(SELECTOR_RPL_FLAG | SELECTOR_TI_FLAG);

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
    g_vmcs_fields[VMCS_GUEST_CR0] = 0xffffFFFFffffFFFF;
    g_vmcs_fields[VMCS_GUEST_CR3] = 0x0000000000001000;
    g_vmcs_fields[VMCS_GUEST_CR4] = 0xffffFFFFfffdFFFF;
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
    g_vmcs_fields[VMCS_GUEST_RFLAGS] = 0x2 | RFLAGS_IF_INTERRUPT_ENABLE_FLAG;
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
    g_vmcs_fields[VMCS_POSTED_INTERRUPT_NOTIFICATION_VECTOR] = 0x0000000000000000;
    g_vmcs_fields[VMCS_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS_FULL] = 0x0000000010000000;
    g_vmcs_fields[VMCS_VIRTUAL_PROCESSOR_IDENTIFIER] = 0x0000000000000002;
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
    g_vmcs_fields[VMCS_GUEST_CR0] = CRO_PE_PROTECTION_ENABLE;
    g_vmcs_fields[VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE] = 0x0;
    g_vmcs_fields[VMCS_VM_ENTRY_MSR_LOAD_COUNT] = 0xff0000;
    g_vmcs_fields[VMCS_VM_ENTRY_MSR_LOAD_ADDRESS_FULL] = 0x0000000010000000;
}

void
setup_msrs()
{
    g_msrs[IA32_VMX_BASIC_MSR] = 0x7ffFFFF;
    g_msrs[IA32_VMX_TRUE_PINBASED_CTLS_MSR] = 0xffffFFFF01010101;
    g_msrs[IA32_VMX_TRUE_PROCBASED_CTLS_MSR] = 0xffffFFFF01010101;
    g_msrs[IA32_VMX_PROCBASED_CTLS2_MSR] = 0xffffFdeefffffdee;
    g_msrs[IA32_VMX_EPT_VPID_CAP_MSR] = IA32_VMX_EPT_VPID_CAP_UC | IA32_VMX_EPT_VPID_CAP_WB | IA32_VMX_EPT_VPID_CAP_AD;
    g_msrs[IA32_VMX_VMFUNC_MSR] = 0xffffFFFFffffFFFF;
    g_msrs[IA32_VMX_TRUE_EXIT_CTLS_MSR] = 0xffffFFFF01010101;
    g_msrs[IA32_VMX_TRUE_ENTRY_CTLS_MSR] = 0xffffFFFF01010101;

    g_msrs[IA32_VMX_CR0_FIXED0_MSR] = 0x0;
    g_msrs[IA32_VMX_CR0_FIXED1_MSR] = 0xffffFFFFffffFFFF;
    g_msrs[IA32_VMX_CR4_FIXED0_MSR] = 0x0;
    g_msrs[IA32_VMX_CR4_FIXED1_MSR] = 0xffffFFFFffffFFFF;

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
    // Setup 16 bit state functions
    mocks.OnCall(state_in, vmcs_intel_x64_state::es).Do(es);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs).Do(cs);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss).Do(ss);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds).Do(ds);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs).Do(fs);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs).Do(gs);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr).Do(ldtr);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr).Do(tr);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gdt_limit).Do(gdt_limit);
    mocks.OnCall(state_in, vmcs_intel_x64_state::idt_limit).Do(idt_limit);

    // Setup 32 bit state functions
    mocks.OnCall(state_in, vmcs_intel_x64_state::es_limit).Do(es_limit);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs_limit).Do(cs_limit);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss_limit).Do(ss_limit);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_limit).Do(ds_limit);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_limit).Do(ds_limit);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs_limit).Do(fs_limit);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs_limit).Do(gs_limit);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr_limit).Do(ldtr_limit);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr_limit).Do(tr_limit);

    mocks.OnCall(state_in, vmcs_intel_x64_state::es_access_rights).Do(es_access_rights);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs_access_rights).Do(cs_access_rights);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss_access_rights).Do(ss_access_rights);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_access_rights).Do(ds_access_rights);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_access_rights).Do(ds_access_rights);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs_access_rights).Do(fs_access_rights);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs_access_rights).Do(gs_access_rights);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr_access_rights).Do(ldtr_access_rights);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr_access_rights).Do(tr_access_rights);

    // Setup 64 bit state functions
    mocks.OnCall(state_in, vmcs_intel_x64_state::cr0).Do(cr0);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cr3).Do(cr3);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cr4).Do(cr4);
    mocks.OnCall(state_in, vmcs_intel_x64_state::dr7).Do(dr7);
    mocks.OnCall(state_in, vmcs_intel_x64_state::rflags).Do(rflags);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gdt_base).Do(gdt_base);
    mocks.OnCall(state_in, vmcs_intel_x64_state::idt_base).Do(idt_base);

    mocks.OnCall(state_in, vmcs_intel_x64_state::es_base).Do(es_base);
    mocks.OnCall(state_in, vmcs_intel_x64_state::cs_base).Do(cs_base);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ss_base).Do(ss_base);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_base).Do(ds_base);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ds_base).Do(ds_base);
    mocks.OnCall(state_in, vmcs_intel_x64_state::fs_base).Do(fs_base);
    mocks.OnCall(state_in, vmcs_intel_x64_state::gs_base).Do(gs_base);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ldtr_base).Do(ldtr_base);
    mocks.OnCall(state_in, vmcs_intel_x64_state::tr_base).Do(tr_base);

    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_debugctl_msr).Do(ia32_debugctl_msr);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_pat_msr).Do(ia32_pat_msr);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_efer_msr).Do(ia32_efer_msr);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_perf_global_ctrl_msr).Do(ia32_perf_global_ctrl_msr);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_cs_msr).Do(ia32_sysenter_cs_msr);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_esp_msr).Do(ia32_sysenter_esp_msr);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_sysenter_eip_msr).Do(ia32_sysenter_eip_msr);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_fs_base_msr).Do(ia32_fs_base_msr);
    mocks.OnCall(state_in, vmcs_intel_x64_state::ia32_gs_base_msr).Do(ia32_gs_base_msr);

    mocks.OnCall(state_in, vmcs_intel_x64_state::dump);
}

static void
setup_vmcs_launch_failure(MockRepository &mocks, intrinsics_intel_x64 *in)
{
    setup_msrs();
    setup_vmcs_fields();

    Call &vmlaunch = mocks.OnCall(in, intrinsics_intel_x64::vmlaunch).Return(false);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).After(vmlaunch).Do(read_msr);
    mocks.OnCall(in, intrinsics_intel_x64::vmread).After(vmlaunch).Do(vmread);
}

static void
setup_vmcs_intrinsics(MockRepository &mocks, memory_manager *mm, intrinsics_intel_x64 *in)
{
    // Emulate the memory manager
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCall(mm, memory_manager::virtptr_to_physint).Do(virtptr_to_physint);
    mocks.OnCall(mm, memory_manager::physint_to_virtptr).Do(physint_to_virtptr);

    mocks.OnCall(in, intrinsics_intel_x64::read_msr).Do(read_msr);
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

        EXPECT_NO_EXCEPTION(vmcs.launch(host_state, guest_state));
    });
}

void
vmcs_ut::test_constructor_null_intrinsics()
{
    EXPECT_NO_EXCEPTION(vmcs_intel_x64(nullptr));
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

        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), std::runtime_error);
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

        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), std::logic_error);
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

        g_new_throws_bad_alloc = STACK_SIZE;
        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), std::bad_alloc);
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

        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), std::runtime_error);
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

        EXPECT_EXCEPTION(vmcs.launch(host_state, guest_state), std::runtime_error);
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

        EXPECT_EXCEPTION(vmcs.promote(), std::runtime_error);
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

        EXPECT_EXCEPTION(vmcs.resume(), std::runtime_error);
    });
}

void
vmcs_ut::test_vmread_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmread).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);
        uint64_t field = 0;

        EXPECT_EXCEPTION(vmcs.vmread(field), std::runtime_error);
    });
}

void
vmcs_ut::test_vmwrite_failure()
{
    MockRepository mocks;
    auto in = bfn::mock_shared<intrinsics_intel_x64>(mocks);

    mocks.OnCall(in.get(), intrinsics_intel_x64::vmwrite).Return(false);

    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs(in);
        uint64_t field = 0;
        uint64_t value = 2;

        EXPECT_EXCEPTION(vmcs.vmwrite(field, value), std::runtime_error);
    });
}
