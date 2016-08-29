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
#include <vmcs/vmcs_intel_x64.h>
#include <memory_manager/memory_manager.h>

static std::map<uint32_t, uint64_t> g_msrs;
static std::map<uint64_t, uint64_t> g_vmcs_fields;

static uint64_t
read_msr(uint32_t msr)
{
    return g_msrs[msr];
}

static void
write_msr(uint32_t msr, uint64_t val)
{
    g_msrs[msr] = val;
}

static bool
vmread(uint64_t field, uint64_t *val)
{
    *val = g_vmcs_fields[field];
    return true;
}

static bool
vmwrite(uint64_t field, uint64_t val)
{
    g_vmcs_fields[field] = val;
    return true;
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

static void dump() {}

static uintptr_t
virt_to_phys_ptr(void *ptr)
{
    (void) ptr;

    return 0x0000000ABCDEF0000;
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

    mocks.OnCall(state_in, vmcs_intel_x64_state::dump).Do(dump);
}

static void
setup_vmcs_intrinsics(MockRepository &mocks, memory_manager *mm, intrinsics_intel_x64 *in)
{
    // Emulate the memory manager
    mocks.OnCallFunc(memory_manager::instance).Return(mm);
    mocks.OnCallOverload(mm, (uintptr_t(memory_manager::*)(void *))&memory_manager::virt_to_phys).Do(virt_to_phys_ptr);

    // Setup MSR and vmread returns to mock a successful vmcs_intel_x64::filter_unsupported
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_BASIC_MSR).Return(0x7fffFFFF);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PINBASED_CTLS_MSR).Return(0x55555555aaaaAAAA);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_PROCBASED_CTLS_MSR).Return(0x55555555aaaaAAAA);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_PROCBASED_CTLS2_MSR).Return(0x55555555aaaaAAAA);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_EXIT_CTLS_MSR).Return(0x55555555aaaaAAAA);
    mocks.OnCall(in, intrinsics_intel_x64::read_msr).With(IA32_VMX_TRUE_ENTRY_CTLS_MSR).Return(0x55555555aaaaAAAA);
    mocks.OnCall(in, intrinsics_intel_x64::vmread).Return(0x5555555555555555);

    mocks.OnCall(in, intrinsics_intel_x64::read_msr).Do(read_msr);
    mocks.OnCall(in, intrinsics_intel_x64::write_msr).Do(write_msr);
    mocks.OnCall(in, intrinsics_intel_x64::vmread).Do(vmread);
    mocks.OnCall(in, intrinsics_intel_x64::vmwrite).Do(vmwrite);

    // Make the default return of the vm* calls true
    mocks.OnCall(in, intrinsics_intel_x64::vmclear).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmptrld).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmwrite).Return(true);
    mocks.OnCall(in, intrinsics_intel_x64::vmlaunch).Return(true);
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
