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

#include <hve/arch/intel_x64/vmx/vmx.h>
#include <hve/arch/intel_x64/vmcs/vmcs.h>
#include <hve/arch/intel_x64/check/check.h>
#include <hve/arch/intel_x64/exit_handler/exit_handler.h>

#include <hve/arch/x64/gdt.h>
#include <hve/arch/x64/idt.h>

#include <intrinsics.h>
#include <bfnewdelete.h>

#include <memory_manager/map_ptr_x64.h>
#include <memory_manager/memory_manager_x64.h>
#include <memory_manager/root_page_table_x64.h>

bfvmm::intel_x64::save_state_t g_save_state{};

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;
std::map<uint32_t, uint32_t> g_eax_cpuid;
std::map<uint32_t, uint32_t> g_ebx_cpuid;
std::map<uint32_t, uint32_t> g_ecx_cpuid;

x64::rflags::value_type g_rflags = 0;
intel_x64::cr0::value_type g_cr0 = 0;
intel_x64::cr3::value_type g_cr3 = 0;
intel_x64::cr4::value_type g_cr4 = 0;
intel_x64::dr7::value_type g_dr7 = 0;

uint16_t g_es;
uint16_t g_cs;
uint16_t g_ss;
uint16_t g_ds;
uint16_t g_fs;
uint16_t g_gs;
uint16_t g_ldtr;
uint16_t g_tr;

::x64::gdt_reg::reg_t g_gdtr{};
::x64::idt_reg::reg_t g_idtr{};

std::vector<bfvmm::x64::gdt::segment_descriptor_type> g_gdt = {
    0x0,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFF7FFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFF8FFFFFFFFFFF,
    0x00000000FFFFFFFF,
};

std::vector<bfvmm::x64::idt::interrupt_descriptor_type> g_idt = {
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF
};

alignas(0x1000) static char g_map[100];

bool g_virt_to_phys_fails = false;
bool g_phys_to_virt_fails = false;
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

std::map<uint64_t, void *> g_mock_mem {
    {
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

extern "C" uint64_t
_read_dr7() noexcept
{ return g_dr7; }

extern "C" void
_write_dr7(uint64_t val) noexcept
{ g_dr7 = val; }

extern "C" uint64_t
_read_rflags(void) noexcept
{ return g_rflags; }

extern "C" void
_write_rflags(uint64_t val) noexcept
{ g_rflags = val; }

extern "C" uint16_t
_read_es() noexcept
{ return g_es; }

extern "C" uint16_t
_read_cs() noexcept
{ return g_cs; }

extern "C" uint16_t
_read_ss() noexcept
{ return g_ss; }

extern "C" uint16_t
_read_ds() noexcept
{ return g_ds; }

extern "C" uint16_t
_read_fs() noexcept
{ return g_fs; }

extern "C" uint16_t
_read_gs() noexcept
{ return g_gs; }

extern "C" uint16_t
_read_tr() noexcept
{ return g_tr; }

extern "C" uint16_t
_read_ldtr() noexcept
{ return g_ldtr; }

extern "C" void
_write_es(uint16_t val) noexcept
{ g_es = val; }

extern "C" void
_write_cs(uint16_t val) noexcept
{ g_cs = val; }

extern "C" void
_write_ss(uint16_t val) noexcept
{ g_ss = val; }

extern "C" void
_write_ds(uint16_t val) noexcept
{ g_ds = val; }

extern "C" void
_write_fs(uint16_t val) noexcept
{ g_fs = val; }

extern "C" void
_write_gs(uint16_t val) noexcept
{ g_gs = val; }

extern "C" void
_write_tr(uint16_t val) noexcept
{ g_tr = val; }

extern "C" void
_write_ldtr(uint16_t val) noexcept
{ g_ldtr = val; }

extern "C" void
_read_gdt(void *gdt_reg) noexcept
{ *static_cast<::x64::gdt_reg::reg_t *>(gdt_reg) = g_gdtr; }

extern "C" void
_read_idt(void *idt_reg) noexcept
{ *static_cast<::x64::idt_reg::reg_t *>(idt_reg) = g_idtr; }

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
_vmread(uint64_t field, uint64_t *value) noexcept
{
    *value = g_vmcs_fields[field];
    return true;
}

extern "C" bool
_vmwrite(uint64_t field, uint64_t value) noexcept
{
    g_vmcs_fields[field] = value;
    return true;
}

extern "C" bool
_vmptrld(void *ptr) noexcept
{ (void)ptr; return !g_vmload_fails; }

extern "C" bool
_vmlaunch_demote() noexcept
{ return !g_vmlaunch_fails; }

extern "C" bool
_vmxon(void *ptr) noexcept
{ bfignored(ptr); return !g_vmxon_fails; }

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

extern "C" void vmcs_launch(
    bfvmm::intel_x64::save_state_t *save_state) noexcept
{ bfignored(save_state); }

extern "C" void vmcs_promote(
    bfvmm::intel_x64::save_state_t *save_state, const void *gdt) noexcept
{ bfignored(save_state); bfignored(gdt); }

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept
{ bfignored(save_state); }

extern "C" void exit_handler_entry(void)
{ }

void
setup_msrs()
{
    g_msrs[intel_x64::msrs::ia32_vmx_basic::addr] = (1ULL << 55) | (6ULL << 50);

    g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000UL;
    g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xFFFFFFFF00000000UL;

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

void
setup_gdt()
{
    auto limit = g_gdt.size() * sizeof(bfvmm::x64::gdt::segment_descriptor_type) - 1;

    g_gdtr.base = reinterpret_cast<uint64_t>(&g_gdt.at(0));
    g_gdtr.limit = gsl::narrow_cast<uint16_t>(limit);
}

void
setup_idt()
{
    auto limit = g_idt.size() * sizeof(bfvmm::x64::idt::interrupt_descriptor_type) - 1;

    g_idtr.base = reinterpret_cast<uint64_t>(&g_idt.at(0));
    g_idtr.limit = gsl::narrow_cast<uint16_t>(limit);
}

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

// template<typename T> auto
// mock_no_delete(MockRepository &mocks)
// {
//     auto ptr = mocks.Mock<T>();
//     mocks.OnCallDestructor(ptr);

//     return ptr;
// }

// template <typename T> auto
// mock_unique(MockRepository &mocks)
// {
//     return std::unique_ptr<T>(mock_no_delete<T>(mocks));
// }

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
    mocks.OnCall(pt, root_page_table_x64::cr3).Return(0x000000ABCDEF0000);

    return pt;
}

// auto
// setup_vmcs_state(MockRepository &mocks)
// {
//     auto state = mocks.Mock<bfvmm::intel_x64::vmcs_state>();

//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::es).Return(0x10);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::cs).Return(0x10);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ss).Return(0x10);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ds).Return(0x10);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::fs).Return(0x10);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::gs).Return(0x10);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ldtr).Return(0x10);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::tr).Return(0x10);

//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::gdt_limit).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::idt_limit).Return(0);

//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::es_limit).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::cs_limit).Return(0xFFFFFFFF);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ss_limit).Return(0xFFFFFFFF);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ds_limit).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::fs_limit).Return(0xFFFFFFFF);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::gs_limit).Return(0xFFFFFFFF);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ldtr_limit).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::tr_limit).Return(sizeof(tss));

//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::es_access_rights).Return(access_rights::unusable);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::cs_access_rights).Return(access_rights::ring0_cs_descriptor);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ss_access_rights).Return(access_rights::ring0_ss_descriptor);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ds_access_rights).Return(access_rights::unusable);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::fs_access_rights).Return(access_rights::ring0_fs_descriptor);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::gs_access_rights).Return(access_rights::ring0_gs_descriptor);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ldtr_access_rights).Return(access_rights::unusable);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::tr_access_rights).Return(access_rights::ring0_tr_descriptor);

//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::es_base).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::cs_base).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ss_base).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ds_base).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ds_base).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::fs_base).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::gs_base).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ldtr_base).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::tr_base).Return(0);

//     auto cr0 = 0UL;
//     cr0 |= cr0::paging::mask;
//     cr0 |= cr0::protection_enable::mask;

//     auto cr4 = 0UL;
//     cr4 |= cr4::physical_address_extensions::mask;

//     auto rflags = 0UL;
//     rflags |= rflags::interrupt_enable_flag::mask;

//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::cr0).Return(cr0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::cr3).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::cr4).Return(cr4);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::dr7).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::rflags).Return(rflags);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::gdt_base).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::idt_base).Return(0);

//     auto efer = 0UL;
//     efer |= intel_x64::msrs::ia32_efer::lme::mask;
//     efer |= intel_x64::msrs::ia32_efer::lma::mask;

//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ia32_debugctl_msr).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ia32_pat_msr).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ia32_efer_msr).Return(efer);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ia32_perf_global_ctrl_msr).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ia32_sysenter_cs_msr).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ia32_sysenter_esp_msr).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ia32_sysenter_eip_msr).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ia32_fs_base_msr).Return(0);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::ia32_gs_base_msr).Return(0);

//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::is_guest).Return(false);
//     mocks.OnCall(state, bfvmm::intel_x64::vmcs_state::dump);

//     return state;
// }

// inline void
// proc_ctl_allow1(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] |= mask << 32; }

// inline void
// proc_ctl_allow0(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] &= ~mask; }

// inline void
// proc_ctl_disallow1(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] &= ~(mask << 32); }

// inline void
// proc_ctl2_allow1(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] |= mask << 32; }

// inline void
// proc_ctl2_allow0(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] &= ~mask; }

// inline void
// proc_ctl2_disallow1(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] &= ~(mask << 32); }

// inline void
// pin_ctl_allow1(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] |= mask << 32; }

// inline void
// pin_ctl_allow0(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] &= ~mask; }

// inline void
// exit_ctl_allow1(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] |= mask << 32; }

// inline void
// exit_ctl_allow0(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] &= ~mask; }

// inline void
// entry_ctl_allow1(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] |= mask << 32; }

// inline void
// entry_ctl_allow0(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] &= ~mask; }

// inline void
// vmfunc_ctl_allow1(uint64_t mask)
// { g_msrs[intel_x64::msrs::ia32_vmx_vmfunc::addr] |= mask; }

// inline void
// setup_check_control_vm_execution_control_fields_all_paths(std::vector<struct control_flow_path>
//         &cfg)
// {
//     struct control_flow_path path;

//     path.setup = [&] {
//         g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;
//         g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
//         g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;
//         cr3_target_count::set(3UL);
//         primary_processor_based_vm_execution_controls::use_io_bitmaps::disable();
//         primary_processor_based_vm_execution_controls::use_msr_bitmap::disable();
//         primary_processor_based_vm_execution_controls::use_tpr_shadow::disable();
//         secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::disable();
//         secondary_processor_based_vm_execution_controls::apic_register_virtualization::disable();
//         secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::disable();
//         pin_based_vm_execution_controls::nmi_exiting::enable();
//         pin_based_vm_execution_controls::virtual_nmis::enable();
//         secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::disable();
//         pin_based_vm_execution_controls::process_posted_interrupts::disable();
//         secondary_processor_based_vm_execution_controls::enable_vpid::disable();
//         secondary_processor_based_vm_execution_controls::enable_ept::disable();
//         secondary_processor_based_vm_execution_controls::enable_pml::disable();
//         secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
//         secondary_processor_based_vm_execution_controls::enable_vm_functions::disable();
//         secondary_processor_based_vm_execution_controls::vmcs_shadowing::disable();
//         secondary_processor_based_vm_execution_controls::ept_violation_ve::disable();
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_control_vm_exit_control_fields_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;

//     path.setup = [&] {
//         g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;
//         pin_ctl_allow1(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::mask);
//         pin_based_vm_execution_controls::activate_vmx_preemption_timer::enable();
//         vm_exit_msr_store_count::set(0UL);
//         vm_exit_msr_load_count::set(0UL);
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_control_vm_entry_control_fields_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;

//     path.setup = [&] {
//         g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;
//         vm_entry_interruption_information::valid_bit::disable();
//         vm_entry_msr_load_count::set(0UL);
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_control_vmx_controls_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;
//     std::vector<struct control_flow_path> sub_cfg;

//     setup_check_control_vm_execution_control_fields_all_paths(sub_cfg);
//     setup_check_control_vm_exit_control_fields_all_paths(sub_cfg);
//     setup_check_control_vm_entry_control_fields_all_paths(sub_cfg);

//     path.setup = [sub_cfg] {
//         for (const auto &sub_path : sub_cfg)
//         { sub_path.setup(); }
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_guest_control_registers_debug_registers_and_msrs_all_paths(
//     std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;

//     path.setup = [&] {
//         g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000ULL;
//         g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0ULL;
//         g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL;
//         guest_cr0::paging::disable();
//         g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0ULL;
//         g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL;
//         vm_entry_controls::load_debug_controls::disable();
//         vm_entry_controls::ia_32e_mode_guest::disable();
//         guest_cr4::pcid_enable_bit::disable();
//         g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
//         guest_cr3::set(0x1000UL);
//         guest_ia32_sysenter_esp::set(0x1000UL);
//         guest_ia32_sysenter_eip::set(0x1000UL);
//         vm_entry_controls::load_ia32_perf_global_ctrl::disable();
//         vm_entry_controls::load_ia32_pat::disable();
//         vm_entry_controls::load_ia32_efer::disable();
//         vm_entry_controls::load_ia32_bndcfgs::disable();
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_guest_segment_registers_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;

//     path.setup = [&] {
//         guest_tr_selector::ti::disable();
//         guest_ldtr_access_rights::unusable::enable();
//         guest_rflags::virtual_8086_mode::enable();
//         guest_cs_selector::set(0x1UL);
//         guest_cs_base::set(0x10UL);
//         guest_ss_selector::set(0x1UL);
//         guest_ss_base::set(0x10UL);
//         guest_ds_selector::set(0x1UL);
//         guest_ds_base::set(0x10UL);
//         guest_es_selector::set(0x1UL);
//         guest_es_base::set(0x10UL);
//         guest_fs_selector::set(0x1UL);
//         guest_fs_base::set(0x10UL);
//         guest_gs_selector::set(0x1UL);
//         guest_gs_base::set(0x10UL);
//         guest_tr_base::set(0x10UL);
//         guest_cs_limit::set(0xFFFFUL);
//         guest_ss_limit::set(0xFFFFUL);
//         guest_ds_limit::set(0xFFFFUL);
//         guest_es_limit::set(0xFFFFUL);
//         guest_gs_limit::set(0xFFFFUL);
//         guest_fs_limit::set(0xFFFFUL);
//         guest_cs_access_rights::set(0xF3UL);
//         guest_ss_access_rights::set(0xF3UL);
//         guest_ds_access_rights::set(0xF3UL);
//         guest_es_access_rights::set(0xF3UL);
//         guest_fs_access_rights::set(0xF3UL);
//         guest_gs_access_rights::set(0xF3UL);
//         guest_tr_access_rights::type::set(gsl::narrow_cast<uint32_t>(x64::access_rights::type::read_execute_accessed));
//         //guest_tr_access_rights::s::enable();
//         guest_tr_access_rights::present::enable();
//         guest_tr_limit::set(0x1UL);
//         guest_tr_access_rights::granularity::disable();
//         guest_tr_access_rights::unusable::disable();
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_guest_descriptor_table_registers_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;

//     path.setup = [&] {
//         guest_gdtr_base::set(0x1000UL);
//         guest_idtr_base::set(0x1000UL);
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_guest_rip_and_rflags_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;

//     path.setup = [&] {
//         g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000ULL;
//         vm_entry_controls::ia_32e_mode_guest::disable();
//         guest_rip::set(0x1000UL);
//         guest_rflags::reserved::set(0UL);
//         guest_rflags::always_enabled::set(0x2UL);
//         guest_cr0::protection_enable::enable();
//         vm_entry_interruption_information::valid_bit::disable();
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_guest_non_register_state_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;

//     path.setup = [&] {
//         g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000ULL;
//         guest_activity_state::set(guest_activity_state::active);
//         guest_interruptibility_state::blocking_by_sti::disable();
//         guest_interruptibility_state::blocking_by_mov_ss::disable();
//         vm_entry_interruption_information::valid_bit::disable();
//         vm_entry_controls::entry_to_smm::disable();
//         guest_interruptibility_state::reserved::set(0UL);
//         guest_interruptibility_state::enclave_interruption::disable();
//         guest_pending_debug_exceptions::reserved::set(0UL);
//         guest_pending_debug_exceptions::rtm::disable();
//         vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFFUL);
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_guest_pdptes_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;
//     path.setup = [&] { guest_cr0::paging::disable(); };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_guest_state_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     std::vector<struct control_flow_path> sub_cfg;
//     struct control_flow_path path;

//     setup_check_guest_control_registers_debug_registers_and_msrs_all_paths(sub_cfg);
//     setup_check_guest_segment_registers_all_paths(sub_cfg);
//     setup_check_guest_descriptor_table_registers_all_paths(sub_cfg);
//     setup_check_guest_rip_and_rflags_all_paths(sub_cfg);
//     setup_check_guest_non_register_state_all_paths(sub_cfg);
//     setup_check_guest_pdptes_all_paths(sub_cfg);

//     path.setup = [sub_cfg] {
//         for (const auto &sub_path : sub_cfg)
//         { sub_path.setup(); }
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_host_control_registers_and_msrs_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;

//     path.setup = [&] {
//         g_eax_cpuid[0x80000008ULL] = 48UL;
//         g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0ULL;                  // allow cr0 and
//         g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL; // cr4 bits to be
//         g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0ULL;                  // either 0 or 1
//         g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL; //
//         host_cr3::set(0x1000UL); // host_cr3 is valid physical address
//         host_ia32_sysenter_esp::set(0x1000UL); // esp is canonical address
//         host_ia32_sysenter_eip::set(0x1000UL); // eip is canonical address
//         vm_exit_controls::load_ia32_perf_global_ctrl::disable();
//         vm_exit_controls::load_ia32_pat::disable();
//         vm_exit_controls::load_ia32_efer::disable();
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_host_segment_and_descriptor_table_registers_all_paths(
//     std::vector<struct control_flow_path> &cfg)
// {
//     using namespace x64::segment_register;
//     struct control_flow_path path;

//     path.setup = [&] {
//         host_es_selector::ti::disable(); host_es_selector::rpl::set(0UL); // es.ti == 0 && es.rpl == 0
//         host_cs_selector::ti::disable(); host_cs_selector::rpl::set(0UL); // cs.ti == 0 && cs.rpl == 0
//         host_ss_selector::ti::disable(); host_ss_selector::rpl::set(0UL); // ss.ti == 0 && ss.rpl == 0
//         host_ds_selector::ti::disable(); host_ds_selector::rpl::set(0UL); // ds.ti == 0 && ds.rpl == 0
//         host_fs_selector::ti::disable(); host_fs_selector::rpl::set(0UL); // fs.ti == 0 && fs.rpl == 0
//         host_gs_selector::ti::disable(); host_gs_selector::rpl::set(0UL); // gs.ti == 0 && gs.rpl == 0
//         host_tr_selector::ti::disable(); host_tr_selector::rpl::set(0UL); // tr.ti == 0 && tr.rpl == 0

//         host_cs_selector::set(~(cs::ti::mask | cs::rpl::mask)); // cs != 0
//         host_tr_selector::set(~(tr::ti::mask | tr::rpl::mask)); // tr != 0

//         exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
//         vm_exit_controls::host_address_space_size::enable(); // VM-exit ctrl host_address_space_size is 1
//         host_fs_base::set(0x1000UL); // fs base is canonical address
//         host_gs_base::set(0x1000UL); // gs base is canonical address
//         host_gdtr_base::set(0x1000UL); // gdtr base is canonical address
//         host_idtr_base::set(0x1000UL); // idtr base is canonical address
//         host_tr_base::set(0x1000UL); // tr base is canonical address
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_host_address_space_size_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     struct control_flow_path path;

//     path.setup = [&] {
//         g_msrs[intel_x64::msrs::ia32_efer::addr] |= intel_x64::msrs::ia32_efer::lma::mask; // efer.lma == 1
//         exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
//         vm_exit_controls::host_address_space_size::enable(); // VM-exit ctrl host_address_space_size is 1
//         host_cr4::physical_address_extensions::enable(); // host_cr4::physical_address_extensions == 1
//         host_rip::set(0x1000UL); // rip is canonical address
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_host_state_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     std::vector<struct control_flow_path> sub_cfg;
//     struct control_flow_path path;

//     setup_check_host_control_registers_and_msrs_all_paths(sub_cfg);
//     setup_check_host_segment_and_descriptor_table_registers_all_paths(sub_cfg);
//     setup_check_host_address_space_size_all_paths(sub_cfg);

//     path.setup = [sub_cfg] {
//         g_eax_cpuid[0x80000008ULL] = 48UL;
//         for (const auto &sub_path : sub_cfg)
//         { sub_path.setup(); }
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

// inline void
// setup_check_all_paths(std::vector<struct control_flow_path> &cfg)
// {
//     std::vector<struct control_flow_path> sub_cfg;
//     struct control_flow_path path;

//     setup_check_control_vmx_controls_all_paths(sub_cfg);
//     setup_check_host_state_all_paths(sub_cfg);
//     setup_check_guest_state_all_paths(sub_cfg);

//     path.setup = [sub_cfg] {
//         for (const auto &sub_path : sub_cfg)
//         {
//             sub_path.setup();
//         }
//     };
//     path.throws_exception = false;
//     cfg.push_back(path);
// }

#endif
