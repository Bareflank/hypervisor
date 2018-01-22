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

#include <hve/arch/intel_x64/vmxon/vmxon.h>

#include <hve/arch/intel_x64/exit_handler/exit_handler.h>
#include <hve/arch/intel_x64/exit_handler/exit_handler_entry.h>
#include <hve/arch/intel_x64/exit_handler/exit_handler_support.h>

#include <hve/arch/intel_x64/vmcs/vmcs.h>
#include <hve/arch/intel_x64/vmcs/vmcs_check.h>
#include <hve/arch/intel_x64/vmcs/vmcs_launch.h>
#include <hve/arch/intel_x64/vmcs/vmcs_resume.h>
#include <hve/arch/intel_x64/vmcs/vmcs_promote.h>

#include <intrinsics.h>
#include <bfnewdelete.h>

#include <memory_manager/memory_manager_x64.h>
#include <memory_manager/root_page_table_x64.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;
std::map<uint32_t, uint32_t> g_eax_cpuid;
std::map<uint32_t, uint32_t> g_ebx_cpuid;
std::map<uint32_t, uint32_t> g_ecx_cpuid;

uintptr_t g_rip = 0;

vmcs::field_type g_field = 0;
vmcs::value_type g_value = 0;
vmcs::value_type g_exit_reason = 0;
vmcs::value_type g_exit_qualification = 0;
vmcs::value_type g_exit_instruction_length = 8;
vmcs::value_type g_exit_instruction_information = 0;
vmcs::value_type g_guest_cr3 = 0;
vmcs::value_type g_guest_gdtr_limit = 0;
vmcs::value_type g_guest_gdtr_base = 0;

intel_x64::cr0::value_type g_cr0 = 0;
intel_x64::cr3::value_type g_cr3 = 0;
intel_x64::cr4::value_type g_cr4 = 0;
x64::rflags::value_type g_rflags = 0;

alignas(0x1000) static char g_map[100];

auto g_msg = std::string(R"%({"msg":"hello world"})%");
auto g_state_save = state_save_intel_x64 {};

bool g_virt_to_phys_fails = false;
bool g_phys_to_virt_fails = false;
bool g_vmclear_fails = false;
bool g_vmload_fails = false;
bool g_vmlaunch_fails = false;
bool g_vmxon_fails = false;
bool g_vmxoff_fails = false;
bool g_write_cr4_fails = false;

uint64_t g_test_addr = 0U;

uint64_t g_virt_apic_addr = 0U;
uint64_t g_virt_apic_mem[64] = {0U};

uint64_t g_vmcs_link_addr = 1U;
uint64_t g_vmcs_link_mem[1] = {0U};

uint64_t g_pdpt_addr = 2U;
uint64_t g_pdpt_mem[4] = {0U};

std::map<uint64_t, void *> g_mock_mem {{
    {g_virt_apic_addr, static_cast<void *>(&g_virt_apic_mem)},
    {g_vmcs_link_addr, static_cast<void *>(&g_vmcs_link_mem)},
    {g_pdpt_addr, static_cast<void *>(&g_pdpt_mem)}
}};

extern "C" uint64_t
_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

extern "C" void
_write_msr(uint32_t addr, uint64_t val) noexcept
{ g_msrs[addr] = val; }

extern "C" void
_write_gdt(void *gdt_reg) noexcept
{ bfignored(gdt_reg); }

extern "C" void
_write_idt(void *idt_reg) noexcept
{ bfignored(idt_reg); }

extern "C" void
_write_es(uint16_t val) noexcept
{ bfignored(val); }

extern "C" void
_write_cs(uint16_t val) noexcept
{ bfignored(val); }

extern "C" void
_write_ss(uint16_t val) noexcept
{ bfignored(val); }

extern "C" void
_write_ds(uint16_t val) noexcept
{ bfignored(val); }

extern "C" void
_write_fs(uint16_t val) noexcept
{ bfignored(val); }

extern "C" void
_write_gs(uint16_t val) noexcept
{ bfignored(val); }

extern "C" void
_write_ldtr(uint16_t val) noexcept
{ bfignored(val); }

extern "C" void
_write_tr(uint16_t val) noexcept
{ bfignored(val); }

extern "C" uint64_t
_read_cr0(void) noexcept
{ return g_cr0; }

extern "C" uint64_t
_read_cr3(void) noexcept
{ return g_cr3; }

extern "C" uint64_t
_read_cr4(void) noexcept
{ return g_cr4; }

extern "C" void
_write_cr0(uint64_t val) noexcept
{ g_cr0 = val; }

extern "C" void
_write_cr3(uint64_t val) noexcept
{ g_cr3 = val; }

extern "C" void
_write_cr4(uint64_t val) noexcept
{
    if (g_write_cr4_fails) {
        return;
    }

    g_cr4 = val;
}

extern "C" void
_write_dr7(uint64_t val) noexcept
{ bfignored(val); }

extern "C" uint64_t
_read_rflags(void) noexcept
{ return g_rflags; }

extern "C" void
_stop() noexcept
{ }

extern "C" void
_wbinvd() noexcept
{ }

extern "C" void
_invlpg(const void *addr) noexcept
{ bfignored(addr); }

extern "C" void
_cpuid(void *eax, void *ebx, void *ecx, void *edx) noexcept
{
    bfignored(eax);
    bfignored(ebx);
    bfignored(ecx);
    bfignored(edx);
}

extern "C" uint32_t
_cpuid_eax(uint32_t val) noexcept
{ return g_eax_cpuid[val]; }

extern "C" uint32_t
_cpuid_subebx(uint32_t val, uint32_t sub) noexcept
{ bfignored(sub); return g_ebx_cpuid[val]; }

extern "C" uint32_t
_cpuid_ecx(uint32_t val) noexcept
{ return g_ecx_cpuid[val]; }

extern "C" bool
_vmread(uint64_t field, uint64_t *val) noexcept
{
    switch (field) {
        case vmcs::exit_reason::addr:
            *val = g_exit_reason;
            break;
        case vmcs::exit_qualification::addr:
            *val = g_exit_qualification;
            break;
        case vmcs::vm_exit_instruction_length::addr:
            *val = g_exit_instruction_length;
            break;
        case vmcs::vm_exit_instruction_information::addr:
            *val = g_exit_instruction_information;
            break;
        case vmcs::guest_linear_address::addr:
            *val = 0x0;
            break;
        case vmcs::guest_physical_address::addr:
            *val = 0x0;
            break;
        case vmcs::guest_cr3::addr:
            *val = g_guest_cr3;
            break;
        case vmcs::guest_gdtr_limit::addr:
            *val = g_guest_gdtr_limit;
            break;
        case vmcs::guest_gdtr_base::addr:
            *val = g_guest_gdtr_base;
            break;
        default:
            g_field = field;
            *val = g_value;
            break;
    }

    return true;
}

extern "C" bool
_vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_field = field;
    g_value = val;

    return true;
}

extern "C" bool
_vmclear(void *ptr) noexcept
{ (void)ptr; return !g_vmclear_fails; }

extern "C" bool
_vmptrld(void *ptr) noexcept
{ (void)ptr; return !g_vmload_fails; }

extern "C" bool
_vmlaunch_demote() noexcept
{ return !g_vmlaunch_fails; }

extern "C" bool
_vmxon(void *ptr) noexcept
{
    bfignored(ptr);
    return !g_vmxon_fails;
}

extern "C" bool
_vmxoff() noexcept
{ return !g_vmxoff_fails; }

extern "C" uint64_t
thread_context_cpuid(void)
{ return 0; }

extern "C" uint64_t
thread_context_tlsptr(void)
{ return 0; }

uintptr_t
virtptr_to_physint(void *ptr)
{
    bfignored(ptr);

    if (g_virt_to_phys_fails) {
        throw gsl::fail_fast("");
    }

    return 0x0000000ABCDEF0000;
}

void *
physint_to_virtptr(uintptr_t ptr)
{
    bfignored(ptr);

    if (g_phys_to_virt_fails) {
        return nullptr;
    }

    return static_cast<void *>(g_mock_mem[g_test_addr]);
}

extern "C" void
vmcs_launch(state_save_intel_x64 *state_save) noexcept
{ }

extern "C" void
vmcs_promote(state_save_intel_x64 *state_save, const void *guest_gdt) noexcept
{ }

extern "C" void
vmcs_resume(state_save_intel_x64 *state_save) noexcept
{ }

void
setup_msrs()
{
    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55) | (6ULL << 50);
    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000UL;

    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0U;
    g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFF;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0U;
    g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFF;

    g_msrs[intel_x64::msrs::ia32_efer::addr] = intel_x64::msrs::ia32_efer::lma::mask;
    g_msrs[intel_x64::msrs::ia32_feature_control::addr] = (0x1ULL << 0);
}

void
setup_cpuid()
{
    g_ecx_cpuid[intel_x64::cpuid::feature_information::addr] = intel_x64::cpuid::feature_information::ecx::vmx::mask;
}

void
setup_registers()
{
    g_cr0 = 0x0;
    g_cr3 = 0x0;
    g_cr4 = 0x0;
    g_rflags = 0x0;
}

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);

    mocks.OnCall(mm, memory_manager_x64::alloc_map).Return(static_cast<char *>(g_map));
    mocks.OnCall(mm, memory_manager_x64::free_map);
    mocks.OnCall(mm, memory_manager_x64::virtptr_to_physint).Do(virtptr_to_physint);
    mocks.OnCall(mm, memory_manager_x64::physint_to_virtptr).Do(physint_to_virtptr);

    mocks.OnCallFunc(bfn::map_with_cr3);
    mocks.OnCallFunc(bfn::virt_to_phys_with_cr3).Return(0x42);

    return mm;
}

auto
setup_pt(MockRepository &mocks)
{
    auto pt = mocks.Mock<root_page_table_x64>();
    mocks.OnCallFunc(root_pt).Return(pt);

    mocks.OnCall(pt, root_page_table_x64::map_4k);
    mocks.OnCall(pt, root_page_table_x64::unmap);

    return pt;
}

auto
setup_vmcs_state(MockRepository &mocks)
{
    auto state = mocks.Mock<vmcs_intel_x64_state>();

    mocks.OnCall(state, vmcs_intel_x64_state::es).Return(0x10);
    mocks.OnCall(state, vmcs_intel_x64_state::cs).Return(0x10);
    mocks.OnCall(state, vmcs_intel_x64_state::ss).Return(0x10);
    mocks.OnCall(state, vmcs_intel_x64_state::ds).Return(0x10);
    mocks.OnCall(state, vmcs_intel_x64_state::fs).Return(0x10);
    mocks.OnCall(state, vmcs_intel_x64_state::gs).Return(0x10);
    mocks.OnCall(state, vmcs_intel_x64_state::ldtr).Return(0x10);
    mocks.OnCall(state, vmcs_intel_x64_state::tr).Return(0x10);

    mocks.OnCall(state, vmcs_intel_x64_state::gdt_limit).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::idt_limit).Return(0);

    mocks.OnCall(state, vmcs_intel_x64_state::es_limit).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::cs_limit).Return(0xFFFFFFFF);
    mocks.OnCall(state, vmcs_intel_x64_state::ss_limit).Return(0xFFFFFFFF);
    mocks.OnCall(state, vmcs_intel_x64_state::ds_limit).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::fs_limit).Return(0xFFFFFFFF);
    mocks.OnCall(state, vmcs_intel_x64_state::gs_limit).Return(0xFFFFFFFF);
    mocks.OnCall(state, vmcs_intel_x64_state::ldtr_limit).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::tr_limit).Return(sizeof(tss_x64));

    mocks.OnCall(state, vmcs_intel_x64_state::es_access_rights).Return(access_rights::unusable);
    mocks.OnCall(state, vmcs_intel_x64_state::cs_access_rights).Return(access_rights::ring0_cs_descriptor);
    mocks.OnCall(state, vmcs_intel_x64_state::ss_access_rights).Return(access_rights::ring0_ss_descriptor);
    mocks.OnCall(state, vmcs_intel_x64_state::ds_access_rights).Return(access_rights::unusable);
    mocks.OnCall(state, vmcs_intel_x64_state::fs_access_rights).Return(access_rights::ring0_fs_descriptor);
    mocks.OnCall(state, vmcs_intel_x64_state::gs_access_rights).Return(access_rights::ring0_gs_descriptor);
    mocks.OnCall(state, vmcs_intel_x64_state::ldtr_access_rights).Return(access_rights::unusable);
    mocks.OnCall(state, vmcs_intel_x64_state::tr_access_rights).Return(access_rights::ring0_tr_descriptor);

    mocks.OnCall(state, vmcs_intel_x64_state::es_base).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::cs_base).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ss_base).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ds_base).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ds_base).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::fs_base).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::gs_base).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ldtr_base).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::tr_base).Return(0);

    auto cr0 = 0UL;
    cr0 |= cr0::paging::mask;
    cr0 |= cr0::protection_enable::mask;

    auto cr4 = 0UL;
    cr4 |= cr4::physical_address_extensions::mask;

    auto rflags = 0UL;
    rflags |= rflags::interrupt_enable_flag::mask;

    mocks.OnCall(state, vmcs_intel_x64_state::cr0).Return(cr0);
    mocks.OnCall(state, vmcs_intel_x64_state::cr3).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::cr4).Return(cr4);
    mocks.OnCall(state, vmcs_intel_x64_state::dr7).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::rflags).Return(rflags);
    mocks.OnCall(state, vmcs_intel_x64_state::gdt_base).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::idt_base).Return(0);

    auto efer = 0UL;
    efer |= intel_x64::msrs::ia32_efer::lme::mask;
    efer |= intel_x64::msrs::ia32_efer::lma::mask;

    mocks.OnCall(state, vmcs_intel_x64_state::ia32_debugctl_msr).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ia32_pat_msr).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ia32_efer_msr).Return(efer);
    mocks.OnCall(state, vmcs_intel_x64_state::ia32_perf_global_ctrl_msr).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ia32_sysenter_cs_msr).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ia32_sysenter_esp_msr).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ia32_sysenter_eip_msr).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ia32_fs_base_msr).Return(0);
    mocks.OnCall(state, vmcs_intel_x64_state::ia32_gs_base_msr).Return(0);

    mocks.OnCall(state, vmcs_intel_x64_state::is_guest).Return(false);
    mocks.OnCall(state, vmcs_intel_x64_state::dump);

    return state;
}

#endif
