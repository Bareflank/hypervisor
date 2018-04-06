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

#include <test/support.h>

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

alignas(0x1000) static char g_map[100];

bool g_virt_to_phys_fails = false;
bool g_phys_to_virt_fails = false;

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
    }
};

void *
physint_to_virtptr(uintptr_t ptr)
{
    bfignored(ptr);

    if (g_phys_to_virt_fails) {
        return nullptr;
    }

    return static_cast<void *>(g_mock_mem[g_test_addr]);
}

auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<bfvmm::memory_manager>();
    mocks.OnCallFunc(bfvmm::memory_manager::instance).Return(mm);

    mocks.OnCall(mm, bfvmm::memory_manager::alloc_map).Return(static_cast<char *>(g_map));
    mocks.OnCall(mm, bfvmm::memory_manager::free_map);
    mocks.OnCall(mm, bfvmm::memory_manager::physint_to_virtptr).Do(physint_to_virtptr);

    return mm;
}

struct control_flow_path {
    std::function<void()> setup{};
    bool throws_exception{false};
} g_path;

inline void
proc_ctl_allow1(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] |= mask << 32; }

inline void
proc_ctl_allow0(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] &= ~mask; }

inline void
proc_ctl_disallow1(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] &= ~(mask << 32); }

inline void
proc_ctl2_allow1(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] |= mask << 32; }

inline void
proc_ctl2_allow0(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] &= ~mask; }

inline void
proc_ctl2_disallow1(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] &= ~(mask << 32); }

inline void
pin_ctl_allow1(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] |= mask << 32; }

inline void
pin_ctl_allow0(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] &= ~mask; }

inline void
exit_ctl_allow1(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] |= mask << 32; }

inline void
exit_ctl_allow0(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] &= ~mask; }

inline void
entry_ctl_allow1(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] |= mask << 32; }

inline void
entry_ctl_allow0(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] &= ~mask; }

inline void
vmfunc_ctl_allow1(uint64_t mask)
{ g_msrs[intel_x64::msrs::ia32_vmx_vmfunc::addr] |= mask; }

void
test_vmcs_check(std::vector<struct control_flow_path> cfg, void(*func)())
{
    for (auto p : cfg) {
        MockRepository mocks;
        setup_mm(mocks);

        p.setup();

        if (p.throws_exception) {
            CHECK_THROWS(func());
        }
        else {
            CHECK_NOTHROW(func());
        }
    }
}

inline void
setup_check_control_vm_execution_control_fields_all_paths(std::vector<struct control_flow_path>
        &cfg)
{
    struct control_flow_path path;

    path.setup = [&] {
        g_msrs[intel_x64::msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;
        g_msrs[intel_x64::msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
        g_msrs[intel_x64::msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;
        cr3_target_count::set(3UL);
        primary_processor_based_vm_execution_controls::use_io_bitmaps::disable();
        primary_processor_based_vm_execution_controls::use_msr_bitmap::disable();
        primary_processor_based_vm_execution_controls::use_tpr_shadow::disable();
        secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::disable();
        secondary_processor_based_vm_execution_controls::apic_register_virtualization::disable();
        secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::disable();
        pin_based_vm_execution_controls::nmi_exiting::enable();
        pin_based_vm_execution_controls::virtual_nmis::enable();
        secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::disable();
        pin_based_vm_execution_controls::process_posted_interrupts::disable();
        secondary_processor_based_vm_execution_controls::enable_vpid::disable();
        secondary_processor_based_vm_execution_controls::enable_ept::disable();
        secondary_processor_based_vm_execution_controls::enable_pml::disable();
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
        secondary_processor_based_vm_execution_controls::enable_vm_functions::disable();
        secondary_processor_based_vm_execution_controls::vmcs_shadowing::disable();
        secondary_processor_based_vm_execution_controls::ept_violation_ve::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_control_vm_exit_control_fields_all_paths(std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;

    path.setup = [&] {
        g_msrs[intel_x64::msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;
        pin_ctl_allow1(intel_x64::msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::mask);
        pin_based_vm_execution_controls::activate_vmx_preemption_timer::enable();
        vm_exit_msr_store_count::set(0UL);
        vm_exit_msr_load_count::set(0UL);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_control_vm_entry_control_fields_all_paths(std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;

    path.setup = [&] {
        g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;
        vm_entry_interruption_information::valid_bit::disable();
        vm_entry_msr_load_count::set(0UL);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_control_vmx_controls_all_paths(std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;
    std::vector<struct control_flow_path> sub_cfg;

    setup_check_control_vm_execution_control_fields_all_paths(sub_cfg);
    setup_check_control_vm_exit_control_fields_all_paths(sub_cfg);
    setup_check_control_vm_entry_control_fields_all_paths(sub_cfg);

    path.setup = [sub_cfg] {
        for (const auto &sub_path : sub_cfg)
        { sub_path.setup(); }
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_guest_control_registers_debug_registers_and_msrs_all_paths(
    std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;

    path.setup = [&] {
        g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000ULL;
        g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0ULL;
        g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL;
        guest_cr0::paging::disable();
        g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0ULL;
        g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL;
        vm_entry_controls::load_debug_controls::disable();
        vm_entry_controls::ia_32e_mode_guest::disable();
        guest_cr4::pcid_enable_bit::disable();
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        guest_cr3::set(0x1000UL);
        guest_ia32_sysenter_esp::set(0x1000UL);
        guest_ia32_sysenter_eip::set(0x1000UL);
        vm_entry_controls::load_ia32_perf_global_ctrl::disable();
        vm_entry_controls::load_ia32_pat::disable();
        vm_entry_controls::load_ia32_efer::disable();
        vm_entry_controls::load_ia32_bndcfgs::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_guest_segment_registers_all_paths(std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;

    path.setup = [&] {
        guest_tr_selector::ti::disable();
        guest_ldtr_access_rights::unusable::enable();
        guest_rflags::virtual_8086_mode::enable();
        guest_cs_selector::set(0x1UL);
        guest_cs_base::set(0x10UL);
        guest_ss_selector::set(0x1UL);
        guest_ss_base::set(0x10UL);
        guest_ds_selector::set(0x1UL);
        guest_ds_base::set(0x10UL);
        guest_es_selector::set(0x1UL);
        guest_es_base::set(0x10UL);
        guest_fs_selector::set(0x1UL);
        guest_fs_base::set(0x10UL);
        guest_gs_selector::set(0x1UL);
        guest_gs_base::set(0x10UL);
        guest_tr_base::set(0x10UL);
        guest_cs_limit::set(0xFFFFUL);
        guest_ss_limit::set(0xFFFFUL);
        guest_ds_limit::set(0xFFFFUL);
        guest_es_limit::set(0xFFFFUL);
        guest_gs_limit::set(0xFFFFUL);
        guest_fs_limit::set(0xFFFFUL);
        guest_cs_access_rights::set(0xF3UL);
        guest_ss_access_rights::set(0xF3UL);
        guest_ds_access_rights::set(0xF3UL);
        guest_es_access_rights::set(0xF3UL);
        guest_fs_access_rights::set(0xF3UL);
        guest_gs_access_rights::set(0xF3UL);
        guest_tr_access_rights::type::set(gsl::narrow_cast<uint32_t>(x64::access_rights::type::read_execute_accessed));
        //guest_tr_access_rights::s::enable();
        guest_tr_access_rights::present::enable();
        guest_tr_limit::set(0x1UL);
        guest_tr_access_rights::granularity::disable();
        guest_tr_access_rights::unusable::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_guest_descriptor_table_registers_all_paths(std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;

    path.setup = [&] {
        guest_gdtr_base::set(0x1000UL);
        guest_idtr_base::set(0x1000UL);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_guest_rip_and_rflags_all_paths(std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;

    path.setup = [&] {
        g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000ULL;
        vm_entry_controls::ia_32e_mode_guest::disable();
        guest_rip::set(0x1000UL);
        guest_rflags::reserved::set(0UL);
        guest_rflags::always_enabled::set(0x2UL);
        guest_cr0::protection_enable::enable();
        vm_entry_interruption_information::valid_bit::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_guest_non_register_state_all_paths(std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;

    path.setup = [&] {
        g_msrs[intel_x64::msrs::ia32_vmx_true_entry_ctls::addr] = 0xFFFFFFFF00000000ULL;
        guest_activity_state::set(guest_activity_state::active);
        guest_interruptibility_state::blocking_by_sti::disable();
        guest_interruptibility_state::blocking_by_mov_ss::disable();
        vm_entry_interruption_information::valid_bit::disable();
        vm_entry_controls::entry_to_smm::disable();
        guest_interruptibility_state::reserved::set(0UL);
        guest_interruptibility_state::enclave_interruption::disable();
        guest_pending_debug_exceptions::reserved::set(0UL);
        guest_pending_debug_exceptions::rtm::disable();
        vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFFUL);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_guest_pdptes_all_paths(std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;
    path.setup = [&] { guest_cr0::paging::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_guest_state_all_paths(std::vector<struct control_flow_path> &cfg)
{
    std::vector<struct control_flow_path> sub_cfg;
    struct control_flow_path path;

    setup_check_guest_control_registers_debug_registers_and_msrs_all_paths(sub_cfg);
    setup_check_guest_segment_registers_all_paths(sub_cfg);
    setup_check_guest_descriptor_table_registers_all_paths(sub_cfg);
    setup_check_guest_rip_and_rflags_all_paths(sub_cfg);
    setup_check_guest_non_register_state_all_paths(sub_cfg);
    setup_check_guest_pdptes_all_paths(sub_cfg);

    path.setup = [sub_cfg] {
        for (const auto &sub_path : sub_cfg)
        { sub_path.setup(); }
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_host_control_registers_and_msrs_all_paths(std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;

    path.setup = [&] {
        g_eax_cpuid[0x80000008ULL] = 48UL;
        g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed0::addr] = 0ULL;                  // allow cr0 and
        g_msrs[intel_x64::msrs::ia32_vmx_cr0_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL; // cr4 bits to be
        g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed0::addr] = 0ULL;                  // either 0 or 1
        g_msrs[intel_x64::msrs::ia32_vmx_cr4_fixed1::addr] = 0xFFFFFFFFFFFFFFFFULL; //
        host_cr3::set(0x1000UL); // host_cr3 is valid physical address
        host_ia32_sysenter_esp::set(0x1000UL); // esp is canonical address
        host_ia32_sysenter_eip::set(0x1000UL); // eip is canonical address
        vm_exit_controls::load_ia32_perf_global_ctrl::disable();
        vm_exit_controls::load_ia32_pat::disable();
        vm_exit_controls::load_ia32_efer::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_host_segment_and_descriptor_table_registers_all_paths(
    std::vector<struct control_flow_path> &cfg)
{
    using namespace x64::segment_register;
    struct control_flow_path path;

    path.setup = [&] {
        host_es_selector::ti::disable(); host_es_selector::rpl::set(0UL); // es.ti == 0 && es.rpl == 0
        host_cs_selector::ti::disable(); host_cs_selector::rpl::set(0UL); // cs.ti == 0 && cs.rpl == 0
        host_ss_selector::ti::disable(); host_ss_selector::rpl::set(0UL); // ss.ti == 0 && ss.rpl == 0
        host_ds_selector::ti::disable(); host_ds_selector::rpl::set(0UL); // ds.ti == 0 && ds.rpl == 0
        host_fs_selector::ti::disable(); host_fs_selector::rpl::set(0UL); // fs.ti == 0 && fs.rpl == 0
        host_gs_selector::ti::disable(); host_gs_selector::rpl::set(0UL); // gs.ti == 0 && gs.rpl == 0
        host_tr_selector::ti::disable(); host_tr_selector::rpl::set(0UL); // tr.ti == 0 && tr.rpl == 0

        host_cs_selector::set(~(cs::ti::mask | cs::rpl::mask)); // cs != 0
        host_tr_selector::set(~(tr::ti::mask | tr::rpl::mask)); // tr != 0

        exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable(); // VM-exit ctrl host_address_space_size is 1
        host_fs_base::set(0x1000UL); // fs base is canonical address
        host_gs_base::set(0x1000UL); // gs base is canonical address
        host_gdtr_base::set(0x1000UL); // gdtr base is canonical address
        host_idtr_base::set(0x1000UL); // idtr base is canonical address
        host_tr_base::set(0x1000UL); // tr base is canonical address
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_host_address_space_size_all_paths(std::vector<struct control_flow_path> &cfg)
{
    struct control_flow_path path;

    path.setup = [&] {
        g_msrs[intel_x64::msrs::ia32_efer::addr] |= intel_x64::msrs::ia32_efer::lma::mask; // efer.lma == 1
        exit_ctl_allow1(intel_x64::msrs::ia32_vmx_true_exit_ctls::host_address_space_size::mask);
        vm_exit_controls::host_address_space_size::enable(); // VM-exit ctrl host_address_space_size is 1
        host_cr4::physical_address_extensions::enable(); // host_cr4::physical_address_extensions == 1
        host_rip::set(0x1000UL); // rip is canonical address
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_host_state_all_paths(std::vector<struct control_flow_path> &cfg)
{
    std::vector<struct control_flow_path> sub_cfg;
    struct control_flow_path path;

    setup_check_host_control_registers_and_msrs_all_paths(sub_cfg);
    setup_check_host_segment_and_descriptor_table_registers_all_paths(sub_cfg);
    setup_check_host_address_space_size_all_paths(sub_cfg);

    path.setup = [sub_cfg] {
        g_eax_cpuid[0x80000008ULL] = 48UL;
        for (const auto &sub_path : sub_cfg)
        { sub_path.setup(); }
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

inline void
setup_check_all_paths(std::vector<struct control_flow_path> &cfg)
{
    std::vector<struct control_flow_path> sub_cfg;
    struct control_flow_path path;

    setup_check_control_vmx_controls_all_paths(sub_cfg);
    setup_check_host_state_all_paths(sub_cfg);
    setup_check_guest_state_all_paths(sub_cfg);

    path.setup = [sub_cfg] {
        for (const auto &sub_path : sub_cfg)
        {
            sub_path.setup();
        }
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

#endif
