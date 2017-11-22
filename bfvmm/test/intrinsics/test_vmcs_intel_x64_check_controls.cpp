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

#include <catch/catch.hpp>
#include <hippomocks.h>
#include <intrinsics/x86/intel_x64.h>
#include <intrinsics/x86/common_x64.h>
#include <test/vmcs_utils.h>
#include <memory_manager/memory_manager_x64.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("test name goes here")
{
    CHECK(true);
}

using namespace intel_x64;
using namespace msrs;
using namespace vmcs;
using namespace check;

struct cpuid_regs g_cpuid_regs;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;
std::map<uint32_t, uint32_t> g_eax_cpuid;

bool g_phys_to_virt_return_nullptr = false;
uint64_t g_test_addr = 0U;
uint64_t g_virt_apic_addr = 0U;
uint8_t g_virt_apic_mem[0x81] = {0U};

std::map<uint64_t, void *> g_mock_mem {
    {
        {g_virt_apic_addr, static_cast<void *>(&g_virt_apic_mem)},
    }
};

uint32_t
test_cpuid_eax(uint32_t val) noexcept
{ return g_eax_cpuid[val]; }

uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

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

static void
setup_intrinsics(MockRepository &mocks, memory_manager_x64 *mm)
{
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::physint_to_virtptr).Do(test_physint_to_virtptr);
    mocks.OnCallFunc(_cpuid_eax).Do(test_cpuid_eax);
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_vmread).Do(test_vmread);
    mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
}

static struct control_flow_path path;

void
test_vmcs_check(std::vector<struct control_flow_path> cfg, void(*func)())
{
    for (auto p : cfg) {
        MockRepository mocks;
        auto mm = mocks.Mock<memory_manager_x64>();
        setup_intrinsics(mocks, mm);

        p.setup();

        if (p.throws_exception) {
            CHECK_THROWS(func());
        }
        else {
            CHECK_NOTHROW(func());
        }
    }
}

static void
setup_check_control_pin_based_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path>
        &cfg)
{
    path.setup = [&] { g_msrs[ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[ia32_vmx_true_pinbased_ctls::addr] = 1; };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { pin_based_vm_execution_controls::set(1UL); };
    path.throws_exception = true;
    cfg.push_back(path);
}

static void
setup_check_control_proc_based_ctls_reserved_properly_set_paths(
    std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[ia32_vmx_true_procbased_ctls::addr] = 1; };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { primary_processor_based_vm_execution_controls::set(1UL); };
    path.throws_exception = true;
    cfg.push_back(path);
}

static void
setup_check_control_proc_based_ctls2_reserved_properly_set_paths(
    std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { proc_ctl_disallow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        g_msrs[ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        g_msrs[ia32_vmx_procbased_ctls2::addr] |= 1;
        secondary_processor_based_vm_execution_controls::set(0UL);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        using namespace secondary_processor_based_vm_execution_controls;

        g_msrs[ia32_vmx_procbased_ctls2::addr] = 0xfffffffe00000000UL;
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();

        // we use the _fields_ set() here rather than the controls enable()
        // so that an exception isn't thrown in the setup function.
        set(virtualize_apic_accesses::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { primary_processor_based_vm_execution_controls::activate_secondary_controls::enable(); };
    path.throws_exception = true;
    cfg.push_back(path);
}

static void
setup_check_control_cr3_count_less_than_4_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { cr3_target_count::set(3UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { cr3_target_count::set(5UL); };
    path.throws_exception = true;
    cfg.push_back(path);
}

static void
setup_check_control_io_bitmap_address_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::use_io_bitmaps::mask);
        primary_processor_based_vm_execution_controls::use_io_bitmaps::disable();
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::use_io_bitmaps::mask);
        primary_processor_based_vm_execution_controls::use_io_bitmaps::enable();
        address_of_io_bitmap_a::set(0x1U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        address_of_io_bitmap_a::set(0xff00000000000000U);
        address_of_io_bitmap_b::set(0x1U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { address_of_io_bitmap_b::set(0xff00000000000000U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { address_of_io_bitmap_a::set(0x1000U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { address_of_io_bitmap_b::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_msr_bitmap_address_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::use_msr_bitmap::mask);
        primary_processor_based_vm_execution_controls::use_msr_bitmap::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::use_msr_bitmap::mask);
        primary_processor_based_vm_execution_controls::use_msr_bitmap::enable();
        address_of_msr_bitmap::set(0x1U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { address_of_msr_bitmap::set(0xff00000000000000U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { address_of_msr_bitmap::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_tpr_shadow_and_virtual_apic_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace primary_processor_based_vm_execution_controls;
    using namespace secondary_processor_based_vm_execution_controls;

    // control paths when tpr shadow is enabled
    path.setup = [&] {
        proc_ctl_allow1(use_tpr_shadow::mask);
        use_tpr_shadow::enable();
        virtual_apic_address::set(0U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { virtual_apic_address::set(1U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { virtual_apic_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(activate_secondary_controls::mask);
        proc_ctl2_allow1(virtual_interrupt_delivery::mask);
        virtual_apic_address::set(0x1000U);
        virtual_interrupt_delivery::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl2_allow0(virtual_interrupt_delivery::mask);
        virtual_interrupt_delivery::disable();
        tpr_threshold::set(0xffffffffffffffffUL);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(activate_secondary_controls::mask);
        proc_ctl2_allow1(virtualize_apic_accesses::mask);
        tpr_threshold::set(0UL);
        virtualize_apic_accesses::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl2_allow0(virtualize_apic_accesses::mask);
        virtualize_apic_accesses::disable();
        g_phys_to_virt_return_nullptr = true;
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_phys_to_virt_return_nullptr = false;
        g_test_addr = g_virt_apic_addr;
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { tpr_threshold::set(0xfUL); };
    path.throws_exception = true;
    cfg.push_back(path);

    // control paths when tpr shadow is disabled
    path.setup = [&] {
        proc_ctl_allow0(activate_secondary_controls::mask);
        proc_ctl_allow0(use_tpr_shadow::mask);
        activate_secondary_controls::disable();
        use_tpr_shadow::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(activate_secondary_controls::mask);
        proc_ctl2_allow1(virtualize_x2apic_mode::mask);
        activate_secondary_controls::enable();
        virtualize_x2apic_mode::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(activate_secondary_controls::mask);
        proc_ctl2_allow0(virtualize_x2apic_mode::mask);
        proc_ctl2_allow1(apic_register_virtualization::mask);
        virtualize_x2apic_mode::disable();
        apic_register_virtualization::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(activate_secondary_controls::mask);
        proc_ctl2_allow0(apic_register_virtualization::mask);
        proc_ctl2_allow1(virtual_interrupt_delivery::mask);
        apic_register_virtualization::disable();
        virtual_interrupt_delivery::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl2_allow0(virtual_interrupt_delivery::mask);
        virtual_interrupt_delivery::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_nmi_exiting_and_virtual_nmi_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        pin_ctl_allow1(ia32_vmx_true_pinbased_ctls::nmi_exiting::mask);
        pin_based_vm_execution_controls::nmi_exiting::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        pin_ctl_allow0(ia32_vmx_true_pinbased_ctls::nmi_exiting::mask);
        pin_ctl_allow1(ia32_vmx_true_pinbased_ctls::virtual_nmis::mask);
        pin_based_vm_execution_controls::nmi_exiting::disable();
        pin_based_vm_execution_controls::virtual_nmis::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        pin_ctl_allow0(ia32_vmx_true_pinbased_ctls::virtual_nmis::mask);
        pin_based_vm_execution_controls::virtual_nmis::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_virtual_nmi_and_nmi_window_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        pin_ctl_allow1(ia32_vmx_true_pinbased_ctls::virtual_nmis::mask);
        pin_based_vm_execution_controls::virtual_nmis::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        pin_ctl_allow1(ia32_vmx_true_pinbased_ctls::virtual_nmis::mask);
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::nmi_window_exiting::mask);
        pin_based_vm_execution_controls::virtual_nmis::disable();
        primary_processor_based_vm_execution_controls::nmi_window_exiting::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::nmi_window_exiting::mask);
        primary_processor_based_vm_execution_controls::nmi_window_exiting::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_virtual_apic_address_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        proc_ctl2_allow1(secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::mask);
        secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::enable();
        apic_access_address::set(0U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { apic_access_address::set(1U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { apic_access_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { apic_access_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_x2apic_mode_and_virtual_apic_access_paths(std::vector<struct control_flow_path>
        &cfg)
{
    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::virtualize_apic_accesses::mask);
        secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::enable();
        secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::virtualize_x2apic_mode::mask);
        secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_virtual_interrupt_and_external_interrupt_paths(
    std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        pin_ctl_allow0(ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::mask);
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
        secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::enable();
        pin_based_vm_execution_controls::external_interrupt_exiting::disable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        pin_ctl_allow1(ia32_vmx_true_pinbased_ctls::external_interrupt_exiting::mask);
        pin_based_vm_execution_controls::external_interrupt_exiting::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_process_posted_interrupt_checks_paths(std::vector<struct control_flow_path>
        &cfg)
{
    path.setup = [&] {
        pin_ctl_allow0(ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask);
        pin_based_vm_execution_controls::process_posted_interrupts::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        pin_ctl_allow1(ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask);
        pin_based_vm_execution_controls::process_posted_interrupts::enable();
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::disable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::mask);
        secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::enable();
        vm_exit_controls::acknowledge_interrupt_on_exit::disable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        exit_ctl_allow1(ia32_vmx_true_exit_ctls::acknowledge_interrupt_on_exit::mask);
        vm_exit_controls::acknowledge_interrupt_on_exit::enable();
        posted_interrupt_notification_vector::set(0x100UL);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        posted_interrupt_notification_vector::set(0U);
        posted_interrupt_descriptor_address::set(1U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { posted_interrupt_descriptor_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { posted_interrupt_descriptor_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_vpid_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::enable_vpid::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::enable_vpid::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::enable_vpid::mask);
        secondary_processor_based_vm_execution_controls::enable_vpid::enable();
        virtual_processor_identifier::set(0U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { virtual_processor_identifier::set(1U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_ept_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        proc_ctl_allow0(primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        proc_ctl2_allow0(secondary_processor_based_vm_execution_controls::enable_ept::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::enable_ept::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        proc_ctl2_allow1(secondary_processor_based_vm_execution_controls::enable_ept::mask);
        secondary_processor_based_vm_execution_controls::enable_ept::enable();
        ept_pointer::memory_type::set(vmcs::ept_pointer::memory_type::uncacheable);
        g_msrs[ia32_vmx_ept_vpid_cap::addr] = ~(ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::mask |
                                                ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::mask);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { ept_pointer::memory_type::set(vmcs::ept_pointer::memory_type::write_back); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { ept_pointer::memory_type::set(3U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_msrs[ia32_vmx_ept_vpid_cap::addr] = ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::mask;
        ept_pointer::memory_type::set(vmcs::ept_pointer::memory_type::write_back);
        ept_pointer::page_walk_length_minus_one::set(0U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        ept_pointer::page_walk_length_minus_one::set(3U);
        ept_pointer::accessed_and_dirty_flags::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        ept_pointer::accessed_and_dirty_flags::disable();
        ept_pointer::reserved::set(0xFF0U);
    };
    path.throws_exception = true;
    cfg.push_back(path);
}

static void
setup_check_control_enable_pml_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::enable_pml::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::enable_pml::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::enable_pml::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::enable_ept::mask);
        secondary_processor_based_vm_execution_controls::enable_pml::enable();
        secondary_processor_based_vm_execution_controls::enable_ept::disable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::enable_ept::mask);
        secondary_processor_based_vm_execution_controls::enable_ept::enable();
        pml_address::set(0xff00000000000000U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { pml_address::set(1U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { pml_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_unrestricted_guests_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::enable_ept::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
        secondary_processor_based_vm_execution_controls::enable_ept::disable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::enable_ept::mask);
        secondary_processor_based_vm_execution_controls::enable_ept::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_vm_functions_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vmcs::secondary_processor_based_vm_execution_controls;

    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        enable_vm_functions::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_disallow1(enable_vm_functions::mask);
        g_vmcs_fields[addr] |= enable_vm_functions::mask;
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(enable_vm_functions::mask);
        vm_function_controls::set(1U);
        g_msrs[ia32_vmx_vmfunc::addr] = 0;
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { vm_function_controls::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::enable_vm_functions::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::enable_ept::mask);
        vmfunc_ctl_allow1(ia32_vmx_vmfunc::eptp_switching::mask);
        g_msrs[msrs::ia32_vmx_vmfunc::addr] |= (ia32_vmx_vmfunc::eptp_switching::mask << 32);
        vm_function_controls::eptp_switching::enable();
        enable_ept::disable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::enable_ept::mask);
        enable_ept::enable();
        secondary_processor_based_vm_execution_controls::enable_ept::enable();
        eptp_list_address::set_if_exists(0x0000000000000FFFULL);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        eptp_list_address::set_if_exists(0xFFFFFFFFFFFFF000ULL);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        eptp_list_address::set(0x1000U);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_vmcs_shadowing_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::vmcs_shadowing::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::vmcs_shadowing::mask);
        secondary_processor_based_vm_execution_controls::vmcs_shadowing::enable();
        vmread_bitmap_address::set(1U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        vmread_bitmap_address::set(0xff00000000000000U);
        vmwrite_bitmap_address::set(1U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { vmwrite_bitmap_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { vmread_bitmap_address::set(0x1000U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { vmwrite_bitmap_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_ept_violation_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        proc_ctl_allow0(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::ept_violation_ve::mask);
        primary_processor_based_vm_execution_controls::activate_secondary_controls::enable();
        secondary_processor_based_vm_execution_controls::ept_violation_ve::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::virtual_interrupt_delivery::mask);
        secondary_processor_based_vm_execution_controls::ept_violation_ve::enable();
        virtualization_exception_information_address::set(1U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { virtualization_exception_information_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { virtualization_exception_information_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_vm_exit_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path>
        &cfg)
{
    path.setup = [&] {
        g_msrs[ia32_vmx_true_exit_ctls::addr] = 0;
        vm_exit_controls::set(0UL);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[ia32_vmx_true_exit_ctls::addr] = 1; };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_activate_and_save_preemption_timer_must_be_0_paths(
    std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] {
        pin_ctl_allow1(ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::mask);
        pin_based_vm_execution_controls::activate_vmx_preemption_timer::enable();
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        pin_ctl_allow0(ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::mask);
        exit_ctl_allow1(ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::mask);
        pin_based_vm_execution_controls::activate_vmx_preemption_timer::disable();
        vm_exit_controls::save_vmx_preemption_timer_value::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        exit_ctl_allow0(ia32_vmx_true_exit_ctls::save_vmx_preemption_timer_value::mask);
        vm_exit_controls::save_vmx_preemption_timer_value::disable();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_exit_msr_store_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { vm_exit_msr_store_count::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        vm_exit_msr_store_count::set(16UL);
        vm_exit_msr_store_address::set(0xfU);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        vm_exit_msr_store_address::set(0xff00000000000000U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        vm_exit_msr_store_address::set(0xfffffffffff0U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        vm_exit_msr_store_address::set(0x10U);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_exit_msr_load_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { vm_exit_msr_load_count::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        vm_exit_msr_load_count::set(16UL);
        vmcs::vm_exit_msr_load_address::set(0xfU);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        vm_exit_msr_load_address::set(0xff00000000000000U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        vm_exit_msr_load_address::set(0xfffffffffff0U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        vm_exit_msr_load_address::set(0x10U);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_vm_entry_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path>
        &cfg)
{
    path.setup = [&] {
        g_msrs[ia32_vmx_true_entry_ctls::addr] = 0;
        vm_entry_controls::set(0UL);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[ia32_vmx_true_entry_ctls::addr] = 1; };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_type_vector_checks_paths(std::vector<struct control_flow_path>
        &cfg)
{
    using namespace vm_entry_interruption_information;

    path.setup = [&] { set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        valid_bit::enable();
        interruption_type::set(interruption_type::reserved);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        interruption_type::set(interruption_type::other_event);
        g_msrs[ia32_vmx_true_procbased_ctls::addr] = 0;
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        interruption_type::set(interruption_type::non_maskable_interrupt);
        vector::set(0xFFUL);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { interruption_type::set(interruption_type::hardware_exception); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        interruption_type::set(interruption_type::other_event);
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::monitor_trap_flag::mask);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { vector::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_delivery_ec_checks_paths(std::vector<struct control_flow_path>
        &cfg)
{
    using namespace vm_entry_interruption_information;

    path.setup = [&] { valid_bit::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow1(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        valid_bit::enable();
        deliver_error_code_bit::enable();
        guest_cr0::set(0U);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        proc_ctl_allow1(ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask);
        proc_ctl2_allow0(ia32_vmx_procbased_ctls2::unrestricted_guest::mask);
        secondary_processor_based_vm_execution_controls::unrestricted_guest::disable();
        interruption_type::set(interruption_type::non_maskable_interrupt);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { interruption_type::set(interruption_type::hardware_exception); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { vector::set(0x8UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { deliver_error_code_bit::disable(); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        vector::set(0x18UL);
        deliver_error_code_bit::enable();
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { deliver_error_code_bit::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_reserved_bits_checks_paths(std::vector<struct control_flow_path>
        &cfg)
{
    using namespace vm_entry_interruption_information;

    path.setup = [&] { set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { valid_bit::enable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { reserved::set(1UL); };
    path.throws_exception = true;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_ec_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vm_entry_interruption_information;

    path.setup = [&] { set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { valid_bit::enable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        deliver_error_code_bit::enable();
        vm_entry_exception_error_code::set(0x8000UL);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { vm_entry_exception_error_code::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_instr_length_checks_paths(std::vector<struct control_flow_path>
        &cfg)
{
    using namespace vm_entry_interruption_information;

    path.setup = [&] { set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        valid_bit::enable();
        interruption_type::set(interruption_type::other_event);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        interruption_type::set(interruption_type::software_interrupt);
        vm_entry_instruction_length::set(0UL);
        g_msrs[ia32_vmx_misc::addr] = 0;
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { vm_entry_instruction_length::set(16UL); };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] { vm_entry_instruction_length::set(1UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_entry_msr_load_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { vm_entry_msr_load_count::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] {
        vm_entry_msr_load_count::set(16UL);
        vm_entry_msr_load_address::set(0xfU);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        vm_entry_msr_load_address::set(0xff00000000000000U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        vm_entry_msr_load_address::set(0xfffffffffff0U);
    };
    path.throws_exception = true;
    cfg.push_back(path);

    path.setup = [&] {
        g_eax_cpuid[x64::cpuid::addr_size::addr] = 48U;
        vm_entry_msr_load_address::set(0x10U);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

TEST_CASE("check_control_vmx_controls_all")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vmx_controls_all_paths(cfg);

    test_vmcs_check(cfg, check::vmx_controls_all);
}

TEST_CASE("check_control_vm_execution_control_fields_all")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vm_execution_control_fields_all_paths(cfg);

    test_vmcs_check(cfg, check::control_vm_execution_control_fields_all);
}

TEST_CASE("check_control_vm_exit_control_fields_all")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vm_exit_control_fields_all_paths(cfg);

    test_vmcs_check(cfg, check::control_vm_exit_control_fields_all);
}

TEST_CASE("check_control_vm_entry_control_fields_all")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vm_entry_control_fields_all_paths(cfg);

    test_vmcs_check(cfg, check::control_vm_entry_control_fields_all);
}

TEST_CASE("check_control_pin_based_ctls_reserved_properly_set")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_pin_based_ctls_reserved_properly_set_paths(cfg);

    test_vmcs_check(cfg, check::control_pin_based_ctls_reserved_properly_set);
}

TEST_CASE("check_control_proc_based_ctls_reserved_properly_set")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_proc_based_ctls_reserved_properly_set_paths(cfg);

    test_vmcs_check(cfg, check::control_proc_based_ctls_reserved_properly_set);
}

TEST_CASE("check_control_proc_based_ctls2_reserved_properly_set")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_proc_based_ctls2_reserved_properly_set_paths(cfg);

    test_vmcs_check(cfg, check::control_proc_based_ctls2_reserved_properly_set);
}

TEST_CASE("check_control_cr3_count_less_than_4")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_cr3_count_less_than_4_paths(cfg);

    test_vmcs_check(cfg, check::control_cr3_count_less_then_4);
}

TEST_CASE("check_control_io_bitmap_address_bits")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_io_bitmap_address_bits_paths(cfg);

    test_vmcs_check(cfg, check::control_io_bitmap_address_bits);
}

TEST_CASE("check_control_msr_bitmap_address_bits")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_msr_bitmap_address_bits_paths(cfg);

    test_vmcs_check(cfg, check::control_msr_bitmap_address_bits);
}

TEST_CASE("check_control_tpr_shadow_and_virtual_apic")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_tpr_shadow_and_virtual_apic_paths(cfg);

    test_vmcs_check(cfg, check::control_tpr_shadow_and_virtual_apic);
}

TEST_CASE("check_control_nmi_exiting_and_virtual_nmi")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_nmi_exiting_and_virtual_nmi_paths(cfg);

    test_vmcs_check(cfg, check::control_nmi_exiting_and_virtual_nmi);
}

TEST_CASE("check_control_virtual_nmi_and_nmi_window")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_virtual_nmi_and_nmi_window_paths(cfg);

    test_vmcs_check(cfg, check::control_virtual_nmi_and_nmi_window);
}

TEST_CASE("check_control_virtual_apic_address_bits")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_virtual_apic_address_bits_paths(cfg);

    test_vmcs_check(cfg, check::control_virtual_apic_address_bits);
}

TEST_CASE("check_control_x2apic_mode_and_virtual_apic_access")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_x2apic_mode_and_virtual_apic_access_paths(cfg);

    test_vmcs_check(cfg, check::control_x2apic_mode_and_virtual_apic_access);
}

TEST_CASE("check_control_virtual_interrupt_and_external_interrupt")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_virtual_interrupt_and_external_interrupt_paths(cfg);

    test_vmcs_check(cfg, check::control_virtual_interrupt_and_external_interrupt);
}

TEST_CASE("check_control_process_posted_interrupt_checks")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_process_posted_interrupt_checks_paths(cfg);

    test_vmcs_check(cfg, check::control_process_posted_interrupt_checks);
}

TEST_CASE("check_control_vpid_checks")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vpid_checks_paths(cfg);

    test_vmcs_check(cfg, check::control_vpid_checks);
}

TEST_CASE("check_control_enable_ept_checks")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_ept_checks_paths(cfg);

    test_vmcs_check(cfg, check::control_enable_ept_checks);
}

TEST_CASE("check_control_enable_pml_checks")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_pml_checks_paths(cfg);

    test_vmcs_check(cfg, check::control_enable_pml_checks);
}

TEST_CASE("check_control_unrestricted_guests")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_unrestricted_guests_paths(cfg);

    test_vmcs_check(cfg, check::control_unrestricted_guests);
}

TEST_CASE("check_control_enable_vm_functions")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_vm_functions_paths(cfg);

    test_vmcs_check(cfg, check::control_enable_vm_functions);
}

TEST_CASE("check_control_enable_vmcs_shadowing")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_vmcs_shadowing_paths(cfg);

    test_vmcs_check(cfg, check::control_enable_vmcs_shadowing);
}

TEST_CASE("check_control_enable_ept_violation_checks")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_ept_violation_checks_paths(cfg);

    test_vmcs_check(cfg, check::control_enable_ept_violation_checks);
}

TEST_CASE("check_control_vm_exit_ctls_reserved_properly_set")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vm_exit_ctls_reserved_properly_set_paths(cfg);

    test_vmcs_check(cfg, check::control_vm_exit_ctls_reserved_properly_set);
}

TEST_CASE("check_control_activate_and_save_preemption_timer_must_be_0")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_activate_and_save_preemption_timer_must_be_0_paths(cfg);

    test_vmcs_check(cfg, check::control_activate_and_save_preemption_timer_must_be_0);
}

TEST_CASE("check_control_exit_msr_store_address")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_exit_msr_store_address_paths(cfg);

    test_vmcs_check(cfg, check::control_exit_msr_store_address);
}

TEST_CASE("check_control_exit_msr_load_address")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_exit_msr_load_address_paths(cfg);

    test_vmcs_check(cfg, check::control_exit_msr_load_address);
}

TEST_CASE("check_control_vm_entry_ctls_reserved_properly_set")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vm_entry_ctls_reserved_properly_set_paths(cfg);

    test_vmcs_check(cfg, check::control_vm_entry_ctls_reserved_properly_set);
}

TEST_CASE("check_control_event_injection_type_vector_checks")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_type_vector_checks_paths(cfg);

    test_vmcs_check(cfg, check::control_event_injection_type_vector_checks);
}

TEST_CASE("check_control_event_injection_delivery_ec_checks")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_delivery_ec_checks_paths(cfg);

    test_vmcs_check(cfg, check::control_event_injection_delivery_ec_checks);
}

TEST_CASE("check_control_event_injection_reserved_bits_checks")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_reserved_bits_checks_paths(cfg);

    test_vmcs_check(cfg, check::control_event_injection_reserved_bits_checks);
}

TEST_CASE("check_control_event_injection_ec_checks")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_ec_checks_paths(cfg);

    test_vmcs_check(cfg, check::control_event_injection_ec_checks);
}

TEST_CASE("check_control_event_injection_instr_length_checks")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_instr_length_checks_paths(cfg);

    test_vmcs_check(cfg, check::control_event_injection_instr_length_checks);
}

TEST_CASE("check_control_entry_msr_load_address")
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_entry_msr_load_address_paths(cfg);

    test_vmcs_check(cfg, check::control_entry_msr_load_address);
}

TEST_CASE("check_control_reserved_properly_set")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    setup_intrinsics(mocks, mm);

    g_msrs[ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;
    vm_entry_controls::set(0x1234UL);

    auto msr_addr = ia32_vmx_true_entry_ctls::addr;
    auto ctls = vm_entry_controls::get();
    auto name = vm_entry_controls::name;

    CHECK_NOTHROW(control_reserved_properly_set(msr_addr, ctls, name));
}

TEST_CASE("check_memory_type_reserved")
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();
    setup_intrinsics(mocks, mm);

    CHECK_FALSE(memory_type_reserved(x64::memory_type::write_through));
    CHECK(memory_type_reserved(8U));
}

#endif
