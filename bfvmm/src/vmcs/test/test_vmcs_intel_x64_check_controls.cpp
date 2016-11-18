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

#include <test.h>
#include <memory_manager/memory_manager_x64.h>
#include <vmcs/vmcs_intel_x64_16bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_control_fields.h>

using namespace intel_x64;

static struct control_flow_path path;

static void
setup_checks_on_vm_execution_control_fields_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL;
        g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL;
        g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;
        vmcs::cr3_target_count::set(3U);
        disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::use_io_bitmaps::mask);
        disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::use_msr_bitmaps::mask);
        disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::use_tpr_shadow::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::apic_register_virtualization::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::mask);
        enable_pin_ctl(vmcs::pin_based_vm_execution_controls::nmi_exiting::mask);
        enable_pin_ctl(vmcs::pin_based_vm_execution_controls::virtual_nmis::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::mask);
        disable_pin_ctl(vmcs::pin_based_vm_execution_controls::process_posted_interrupts::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_vpid::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_ept::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_pml::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_vm_functions::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::vmcs_shadowing::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::ept_violation_ve::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_checks_on_vm_exit_control_fields_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL;
        enable_pin_ctl(vmcs::pin_based_vm_execution_controls::activate_vmx_preemption_timer::mask);
        vmcs::vm_exit_msr_store_count::set(0U);
        vmcs::vm_exit_msr_load_count::set(0U);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_checks_on_vm_entry_control_fields_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;
        vmcs::vm_entry_interruption_information_field::valid_bit::disable();
        vmcs::vm_entry_msr_load_count::set(0U);
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
setup_check_vmcs_control_state_paths(std::vector<struct control_flow_path> &cfg)
{
    std::vector<struct control_flow_path> sub_cfg;

    setup_checks_on_vm_execution_control_fields_paths(sub_cfg);
    setup_checks_on_vm_exit_control_fields_paths(sub_cfg);
    setup_checks_on_vm_entry_control_fields_paths(sub_cfg);

    path.setup = [sub_cfg]
    {
        for (const auto &sub_path : sub_cfg)
            sub_path.setup();
    };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
vmcs_ut::test_check_vmcs_control_state()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_vmcs_control_state_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_vmcs_control_state);
}

void
vmcs_ut::test_checks_on_vm_execution_control_fields()
{
    std::vector<struct control_flow_path> cfg;
    setup_checks_on_vm_execution_control_fields_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::checks_on_vm_execution_control_fields);
}

void
vmcs_ut::test_checks_on_vm_exit_control_fields()
{
    std::vector<struct control_flow_path> cfg;
    setup_checks_on_vm_exit_control_fields_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::checks_on_vm_exit_control_fields);
}

void
vmcs_ut::test_checks_on_vm_entry_control_fields()
{
    std::vector<struct control_flow_path> cfg;
    setup_checks_on_vm_entry_control_fields_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::checks_on_vm_entry_control_fields);
}

void
vmcs_ut::test_check_control_ctls_reserved_properly_set()
{
    MockRepository mocks;
    auto mm = mocks.Mock<memory_manager_x64>();

    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);

    g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000UL;
    vmcs::vm_entry_controls::set(0x1234UL);

    auto msr_addr = msrs::ia32_vmx_true_entry_ctls::addr;
    auto ctls = vmcs::vm_entry_controls::get();
    auto name = vmcs::vm_entry_controls::name;


    RUN_UNITTEST_WITH_MOCKS(mocks, [&]
    {
        vmcs_intel_x64 vmcs{};

        EXPECT_NO_EXCEPTION(vmcs.check_control_ctls_reserved_properly_set(msr_addr, ctls, name));
    });
}

static void
setup_check_control_pin_based_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 0xffffffff00000000UL; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid pin_based_vm_execution_controls"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::pin_based_vm_execution_controls::set(1UL); };
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid pin_based_vm_execution_controls"));
    cfg.push_back(path);
}

static void
setup_check_control_proc_based_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0xffffffff00000000UL; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid primary_processor_based_vm_execution_controls"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::primary_processor_based_vm_execution_controls::set(1UL); };
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid primary_processor_based_vm_execution_controls"));
    cfg.push_back(path);
}

static void
setup_check_control_proc_based_ctls2_reserved_properly_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = ~(msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("secondary controls field doesn't exist"));
    cfg.push_back(path);

    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = msrs::ia32_vmx_true_procbased_ctls::activate_secondary_controls::mask << 32;
        g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xffffffff00000000UL;
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= 1; vmcs::secondary_processor_based_vm_execution_controls::set(0UL); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid secondary_processor_based_vm_execution_controls"));
    cfg.push_back(path);

    path.setup = [&]
    {
        using namespace vmcs::secondary_processor_based_vm_execution_controls;

        g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] = 0xfffffffe00000000UL;
        vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::disable();

        // we use the _fields_ set() here rather than the controls enable()
        // so that an exception isn't thrown in the setup function.
        set(virtualize_apic_accesses::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::enable(); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid secondary_processor_based_vm_execution_controls"));
    cfg.push_back(path);
}

static void
setup_check_control_cr3_count_less_than_4_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { vmcs::cr3_target_count::set(3UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vmcs::cr3_target_count::set(5UL); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("cr3 target count > 4"));
    cfg.push_back(path);
}

static void
setup_check_control_io_bitmap_address_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::use_io_bitmaps::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::use_io_bitmaps::mask); vmcs::address_of_io_bitmap_a::set(0x1U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("io bitmap a addr not page aligned"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::address_of_io_bitmap_a::set(0xff00000000000000U); vmcs::address_of_io_bitmap_b::set(0x1U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("io bitmap b addr not page aligned"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::address_of_io_bitmap_b::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("io bitmap a addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::address_of_io_bitmap_a::set(0x1000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("io bitmap b addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::address_of_io_bitmap_b::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_msr_bitmap_address_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] &= ~msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::mask;
        disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::use_msr_bitmaps::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::use_msr_bitmaps::mask << 32;
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::use_msr_bitmaps::mask);
        vmcs::address_of_msr_bitmaps::set(0x1U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("msr bitmap addr not page aligned"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::address_of_msr_bitmaps::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("msr bitmap addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::address_of_msr_bitmaps::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}


static void
setup_check_control_tpr_shadow_and_virtual_apic_paths(std::vector<struct control_flow_path> &cfg)
{
    // control paths when tpr shadow is enabled
    path.setup = [&]
    {
        proc_ctl_allow1(vmcs::primary_processor_based_vm_execution_controls::use_tpr_shadow::mask);
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::use_tpr_shadow::mask);
        vmcs::virtual_apic_address::set(0U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual apic physical addr is NULL"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::virtual_apic_address::set(1U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual apic addr not 4k aligned"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::virtual_apic_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual apic addr too large"));
    cfg.push_back(path);

    path.setup = [&]
    {
        vmcs::virtual_apic_address::set(0x1000U);
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("tpr_shadow is enabled, but virtual interrupt delivery is enabled"));
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::mask);
        g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= msrs::ia32_vmx_true_procbased_ctls::use_tpr_shadow::mask << 32;
        vmcs::tpr_threshold::set(0xffffffffffffffffUL);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 31:4 of the tpr threshold must be 0"));
    cfg.push_back(path);

    path.setup = [&]
    {
        vmcs::tpr_threshold::set(0UL);
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("tpr_shadow is enabled, but virtual apic is enabled"));
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::mask);
        g_phys_to_virt_return_nullptr = true;
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual apic virtual addr is NULL"));
    cfg.push_back(path);

    path.setup = [&] { g_phys_to_virt_return_nullptr = false; };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vmcs::tpr_threshold::set(0xfUL); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid TPR threshold"));
    cfg.push_back(path);

    // control paths when tpr shadow is disabled
    path.setup = [&]
    {
        disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::use_tpr_shadow::mask);
        disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtualize_x2apic_mode must be disabled if tpr shadow is disabled"));
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::mask);
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::apic_register_virtualization::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("apic_register_virtualization must be disabled if tpr shadow is disabled"));
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::apic_register_virtualization::mask);
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual interrupt delivery must be disabled if tpr shadow is disabled"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::mask); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_nmi_exiting_and_virtual_nmi_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_pin_ctl(vmcs::pin_based_vm_execution_controls::nmi_exiting::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_pin_ctl(vmcs::pin_based_vm_execution_controls::nmi_exiting::mask);
        enable_pin_ctl(vmcs::pin_based_vm_execution_controls::virtual_nmis::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual NMI must be 0 if NMI exiting is 0"));
    cfg.push_back(path);

    path.setup = [&] { disable_pin_ctl(vmcs::pin_based_vm_execution_controls::virtual_nmis::mask); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_virtual_nmi_and_nmi_window_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_pin_ctl(vmcs::pin_based_vm_execution_controls::virtual_nmis::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_pin_ctl(vmcs::pin_based_vm_execution_controls::virtual_nmis::mask);
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::nmi_window_exiting::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("NMI window exiting must be 0 if virtual NMI is 0"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::nmi_window_exiting::mask); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_virtual_apic_address_bits_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        proc_ctl_allow1(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        proc_ctl2_allow1(vmcs::secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::mask);
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::mask);
        vmcs::apic_access_address::set(0U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("apic access physical addr is NULL"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::apic_access_address::set(1U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("apic access addr not 4k aligned"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::apic_access_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("apic access addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::apic_access_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_x2apic_mode_and_virtual_apic_access_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::mask);
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("apic accesses must be 0 if x2 apic mode is 1"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::mask); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_virtual_interrupt_and_external_interrupt_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::mask);
        disable_pin_ctl(vmcs::pin_based_vm_execution_controls::external_interrupt_exiting::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("external interrupt exiting must be 1 if virtual interrupt delivery is 1"));
    cfg.push_back(path);

    path.setup = [&] { enable_pin_ctl(vmcs::pin_based_vm_execution_controls::external_interrupt_exiting::mask); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_process_posted_interrupt_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] = msrs::ia32_vmx_true_pinbased_ctls::process_posted_interrupts::mask << 32;
        disable_pin_ctl(vmcs::pin_based_vm_execution_controls::process_posted_interrupts::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_pin_ctl(vmcs::pin_based_vm_execution_controls::process_posted_interrupts::mask);
        disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual interrupt delivery must be 1 if posted interrupts is 1"));
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("virtual interrupt delivery must be 1 if posted interrupts is 1"));
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::mask);
        disable_exit_ctl(vmcs::vm_exit_controls::acknowledge_interrupt_on_exit::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("ack interrupt on exit must be 1 if posted interrupts is 1"));
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_exit_ctl(vmcs::vm_exit_controls::acknowledge_interrupt_on_exit::mask);
        g_vmcs_fields[vmcs::posted_interrupt_notification_vector::addr] = 0x100;
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 15:8 of the notification vector must be 0 if posted interrupts is 1"));
    cfg.push_back(path);

    path.setup = [&]
    {
        g_vmcs_fields[vmcs::posted_interrupt_notification_vector::addr] = 0;
        vmcs::posted_interrupt_descriptor_address::set(1U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 5:0 of the interrupt descriptor addr must be 0 if posted interrupts is 1"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::posted_interrupt_descriptor_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt descriptor addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::posted_interrupt_descriptor_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_vpid_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_vpid::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_vpid::mask);
        g_vmcs_fields[vmcs::virtual_processor_identifier::addr] = 0;
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("vpid cannot equal 0"));
    cfg.push_back(path);

    path.setup = [&] { g_vmcs_fields[vmcs::virtual_processor_identifier::addr] = 1; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_ept_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&]
    {
        proc_ctl_allow1(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        proc_ctl2_allow1(vmcs::secondary_processor_based_vm_execution_controls::enable_ept::mask);
        disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);

    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_ept::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_ept::mask);
        vmcs::ept_pointer::memory_type::set(vmcs::ept_pointer::memory_type::uncacheable);
        g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = ~(msrs::ia32_vmx_ept_vpid_cap::memory_type_uncacheable_supported::mask |
        msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("hardware does not support ept memory type: uncachable"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::ept_pointer::memory_type::set(vmcs::ept_pointer::memory_type::write_back); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("hardware does not support ept memory type: write-back"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::ept_pointer::memory_type::set(3U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("unknown eptp memory type"));
    cfg.push_back(path);

    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_ept_vpid_cap::addr] = msrs::ia32_vmx_ept_vpid_cap::memory_type_write_back_supported::mask;
        vmcs::ept_pointer::memory_type::set(vmcs::ept_pointer::memory_type::write_back);
        vmcs::ept_pointer::page_walk_length_minus_one::set(0U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("the ept walk-through length must be 1 less than 4, i.e. 3"));
    cfg.push_back(path);

    path.setup = [&]
    {
        vmcs::ept_pointer::page_walk_length_minus_one::set(3U);
        vmcs::ept_pointer::accessed_and_dirty_flags::enable();
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("hardware does not support dirty / accessed flags for ept"));
    cfg.push_back(path);

    path.setup = [&]
    {
        vmcs::ept_pointer::accessed_and_dirty_flags::disable();
        vmcs::ept_pointer::reserved::set(0xFF0U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:7 and 63:48 of the eptp must be 0"));
    cfg.push_back(path);
}

static void
setup_check_control_enable_pml_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_pml::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_pml::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_ept::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("ept must be enabled if pml is enabled"));
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_ept::mask);
        vmcs::pml_address::set(0xff00000000000000U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("pml address must be a valid physical address"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::pml_address::set(1U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:0 of the pml address must be 0"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::pml_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_unrestricted_guests_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_ept::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("enable ept must be 1 if unrestricted guest is 1"));
    cfg.push_back(path);

    path.setup = [&] { enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_ept::mask); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_vm_functions_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_vm_functions::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_vm_functions::mask);
        g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] &= ~(vmcs::secondary_processor_based_vm_execution_controls::enable_vm_functions::mask << 32);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= vmcs::secondary_processor_based_vm_execution_controls::enable_vm_functions::mask << 32;
        vmcs::vm_function_controls::set(1U);
        g_msrs[msrs::ia32_vmx_vmfunc::addr] = 0;
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("unsupported vm function control bit set"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_function_controls::set(0U); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] |= vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask << 32;
        g_msrs[msrs::ia32_vmx_procbased_ctls2::addr] |= vmcs::secondary_processor_based_vm_execution_controls::enable_vm_functions::mask << 32;
        g_msrs[msrs::ia32_vmx_vmfunc::addr] |= vmcs::vm_function_controls::eptp_switching::mask;
        vmcs::vm_function_controls::eptp_switching::enable_if_allowed();
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_ept::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("enable ept must be 1 if eptp switching is 1"));
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::enable_ept::mask);
        vmcs::eptp_list_address::set_if_exists(1U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:0 must be 0 for eptp list address"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::eptp_list_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("eptp list address addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::eptp_list_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_vmcs_shadowing_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::vmcs_shadowing::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::vmcs_shadowing::mask);
        vmcs::vmread_bitmap_address::set(1U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:0 must be 0 for the vmcs read bitmap address"));
    cfg.push_back(path);

    path.setup = [&]
    {
        vmcs::vmread_bitmap_address::set(0xff00000000000000U);
        vmcs::vmwrite_bitmap_address::set(1U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:0 must be 0 for the vmcs write bitmap address"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vmwrite_bitmap_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("vmcs read bitmap address addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vmread_bitmap_address::set(0x1000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("vmcs write bitmap address addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vmwrite_bitmap_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_enable_ept_violation_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { disable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl(vmcs::primary_processor_based_vm_execution_controls::activate_secondary_controls::mask);
        disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::ept_violation_ve::mask);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::ept_violation_ve::mask);
        vmcs::virtualization_exception_information_address::set(1U);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 11:0 must be 0 for the vmcs virt except info address"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::virtualization_exception_information_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("vmcs virt except info address addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::virtualization_exception_information_address::set(0x1000U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_vm_exit_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0; vmcs::vm_exit_controls::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid vm_exit_controls"));
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_exit_ctls::addr] = 0xffffffff00000000UL; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_activate_and_save_preemption_timer_must_be_0_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { enable_pin_ctl(vmcs::pin_based_vm_execution_controls::activate_vmx_preemption_timer::mask); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        disable_pin_ctl(vmcs::pin_based_vm_execution_controls::activate_vmx_preemption_timer::mask);
        enable_exit_ctl(vmcs::vm_exit_controls::save_vmx_preemption_timer_value::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("save vmx preemption timer must be 0 if activate vmx preemption timer is 0"));
    cfg.push_back(path);

    path.setup = [&] { disable_exit_ctl(vmcs::vm_exit_controls::save_vmx_preemption_timer_value::mask); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_exit_msr_store_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { vmcs::vm_exit_msr_store_count::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_exit_msr_store_count::set(16UL); vmcs::vm_exit_msr_store_address::set(0xfU); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 3:0 must be 0 for the exit msr store address"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_exit_msr_store_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("exit msr store addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_exit_msr_store_address::set(0xfffffff0U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("end of exit msr store area too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_exit_msr_store_address::set(0x10U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_exit_msr_load_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { vmcs::vm_exit_msr_load_count::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_exit_msr_load_count::set(16UL); vmcs::vm_exit_msr_load_address::set(0xfU); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 3:0 must be 0 for the exit msr load address"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_exit_msr_load_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("exit msr load addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_exit_msr_load_address::set(0xfffffff0U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("end of exit msr load area too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_exit_msr_load_address::set(0x10U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_vm_entry_ctls_reserved_properly_set_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0; vmcs::vm_entry_controls::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 1; };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("invalid vm_entry_controls"));
    cfg.push_back(path);

    path.setup = [&] { g_msrs[msrs::ia32_vmx_true_entry_ctls::addr] = 0xffffffff00000000; };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_type_vector_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vmcs::vm_entry_interruption_information_field;

    path.setup = [&] { set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { valid_bit::enable(); interruption_type::set(interruption_type::reserved); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field type of 1 is reserved"));
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::other_event);
        g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = 0;
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field type of 7 is reserved on this hardware"));
    cfg.push_back(path);

    path.setup = [&] { interruption_type::set(interruption_type::non_maskable_interrupt); vector::set(0xFFUL); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field vector must be 2 if the type field is 2 (NMI)"));
    cfg.push_back(path);

    path.setup = [&] { interruption_type::set(interruption_type::hardware_exception); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field vector must be 0->31 if the type field is 3 (HE)"));
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::other_event);
        g_msrs[msrs::ia32_vmx_true_procbased_ctls::addr] = msrs::ia32_vmx_true_procbased_ctls::monitor_trap_flag::mask << 32;
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field vector must be 0 if the type field is 7 (other)"));
    cfg.push_back(path);

    path.setup = [&] { vector::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_delivery_ec_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vmcs::vm_entry_interruption_information_field;

    path.setup = [&] { valid_bit::disable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        valid_bit::enable();
        deliver_error_code_bit::enable();
        g_vmcs_fields[vmcs::guest_cr0::addr] = 0;
        enable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::mask);
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("unrestricted guest must be 0 or PE must be enabled in cr0"
                     "if deliver error code bit is set"));
    cfg.push_back(path);

    path.setup = [&] { disable_proc_ctl2(vmcs::secondary_processor_based_vm_execution_controls::unrestricted_guest::mask); interruption_type::set(interruption_type::non_maskable_interrupt); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("interrupt information field type must be 3 if deliver error code bit is set"));
    cfg.push_back(path);

    path.setup = [&] { interruption_type::set(interruption_type::hardware_exception); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("vector must indicate exception that would normally deliver"
                     "an error code if deliver error code bit is set"));
    cfg.push_back(path);

    path.setup = [&] { vector::set(0x8UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { deliver_error_code_bit::disable(); };
    path.throws_exception = true;
    path.exception = std::make_shared<std::logic_error>("deliver_error_code_bit must be 1");
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_reserved_bits_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vmcs::vm_entry_interruption_information_field;

    path.setup = [&] { set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { valid_bit::enable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { reserved::set(1UL); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("reserved bits of the interrupt info field must be 0"));
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_ec_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vmcs::vm_entry_interruption_information_field;

    path.setup = [&] { set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { valid_bit::enable(); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { deliver_error_code_bit::enable(); vmcs::vm_entry_exception_error_code::set(0x8000UL); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 31:15 of the exception error code field must be 0"
                     " if deliver error code bit is set in the interrupt info field"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_entry_exception_error_code::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_event_injection_instr_length_checks_paths(std::vector<struct control_flow_path> &cfg)
{
    using namespace vmcs::vm_entry_interruption_information_field;

    path.setup = [&] { set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        valid_bit::enable();
        interruption_type::set(interruption_type::other_event);
    };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&]
    {
        interruption_type::set(interruption_type::software_interrupt);
        vmcs::vm_entry_instruction_length::set(0UL);
        g_msrs[msrs::ia32_vmx_misc::addr] = 0;
    };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("instruction length must be greater than zero"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_entry_instruction_length::set(16UL); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("instruction length must be in the range of 0-15 if type is 4, 5, 6"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_entry_instruction_length::set(1UL); };
    path.throws_exception = false;
    cfg.push_back(path);
}

static void
setup_check_control_entry_msr_load_address_paths(std::vector<struct control_flow_path> &cfg)
{
    path.setup = [&] { vmcs::vm_entry_msr_load_count::set(0UL); };
    path.throws_exception = false;
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_entry_msr_load_count::set(16UL); vmcs::vm_entry_msr_load_address::set(0xfU); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("bits 3:0 must be 0 for the entry msr load address"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_entry_msr_load_address::set(0xff00000000000000U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("entry msr load addr too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_entry_msr_load_address::set(0xfffffff0U); };
    path.throws_exception = true;
    path.exception = std::shared_ptr<std::exception>(new std::logic_error("end of entry msr load area too large"));
    cfg.push_back(path);

    path.setup = [&] { vmcs::vm_entry_msr_load_address::set(0x10U); };
    path.throws_exception = false;
    cfg.push_back(path);
}

void
vmcs_ut::test_check_control_pin_based_ctls_reserved_properly_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_pin_based_ctls_reserved_properly_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_pin_based_ctls_reserved_properly_set);
}

void
vmcs_ut::test_check_control_proc_based_ctls_reserved_properly_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_proc_based_ctls_reserved_properly_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_proc_based_ctls_reserved_properly_set);
}

void
vmcs_ut::test_check_control_proc_based_ctls2_reserved_properly_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_proc_based_ctls2_reserved_properly_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_proc_based_ctls2_reserved_properly_set);
}

void
vmcs_ut::test_check_control_cr3_count_less_than_4()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_cr3_count_less_than_4_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_cr3_count_less_then_4);
}

void
vmcs_ut::test_check_control_io_bitmap_address_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_io_bitmap_address_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_io_bitmap_address_bits);
}

void
vmcs_ut::test_check_control_msr_bitmap_address_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_msr_bitmap_address_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_msr_bitmap_address_bits);
}

void
vmcs_ut::test_check_control_tpr_shadow_and_virtual_apic()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_tpr_shadow_and_virtual_apic_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_tpr_shadow_and_virtual_apic);
}

void
vmcs_ut::test_check_control_nmi_exiting_and_virtual_nmi()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_nmi_exiting_and_virtual_nmi_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_nmi_exiting_and_virtual_nmi);
}

void
vmcs_ut::test_check_control_virtual_nmi_and_nmi_window()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_virtual_nmi_and_nmi_window_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_virtual_nmi_and_nmi_window);
}

void
vmcs_ut::test_check_control_virtual_apic_address_bits()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_virtual_apic_address_bits_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_virtual_apic_address_bits);
}

void
vmcs_ut::test_check_control_x2apic_mode_and_virtual_apic_access()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_x2apic_mode_and_virtual_apic_access_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_x2apic_mode_and_virtual_apic_access);
}

void
vmcs_ut::test_check_control_virtual_interrupt_and_external_interrupt()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_virtual_interrupt_and_external_interrupt_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_virtual_interrupt_and_external_interrupt);
}

void
vmcs_ut::test_check_control_process_posted_interrupt_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_process_posted_interrupt_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_process_posted_interrupt_checks);
}

void
vmcs_ut::test_check_control_vpid_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vpid_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_vpid_checks);
}

void
vmcs_ut::test_check_control_enable_ept_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_ept_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_enable_ept_checks);
}

void
vmcs_ut::test_check_control_enable_pml_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_pml_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_enable_pml_checks);
}

void
vmcs_ut::test_check_control_unrestricted_guests()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_unrestricted_guests_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_unrestricted_guests);
}

void
vmcs_ut::test_check_control_enable_vm_functions()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_vm_functions_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_enable_vm_functions);
}

void
vmcs_ut::test_check_control_enable_vmcs_shadowing()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_vmcs_shadowing_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_enable_vmcs_shadowing);
}

void
vmcs_ut::test_check_control_enable_ept_violation_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_enable_ept_violation_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_enable_ept_violation_checks);
}

void
vmcs_ut::test_check_control_vm_exit_ctls_reserved_properly_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vm_exit_ctls_reserved_properly_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_vm_exit_ctls_reserved_properly_set);
}

void
vmcs_ut::test_check_control_activate_and_save_preemption_timer_must_be_0()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_activate_and_save_preemption_timer_must_be_0_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_activate_and_save_preemption_timer_must_be_0);
}

void
vmcs_ut::test_check_control_exit_msr_store_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_exit_msr_store_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_exit_msr_store_address);
}

void
vmcs_ut::test_check_control_exit_msr_load_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_exit_msr_load_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_exit_msr_load_address);
}

void
vmcs_ut::test_check_control_vm_entry_ctls_reserved_properly_set()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_vm_entry_ctls_reserved_properly_set_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_vm_entry_ctls_reserved_properly_set);
}

void
vmcs_ut::test_check_control_event_injection_type_vector_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_type_vector_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_event_injection_type_vector_checks);
}

void
vmcs_ut::test_check_control_event_injection_delivery_ec_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_delivery_ec_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_event_injection_delivery_ec_checks);
}

void
vmcs_ut::test_check_control_event_injection_reserved_bits_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_reserved_bits_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_event_injection_reserved_bits_checks);
}

void
vmcs_ut::test_check_control_event_injection_ec_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_ec_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_event_injection_ec_checks);
}

void
vmcs_ut::test_check_control_event_injection_instr_length_checks()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_event_injection_instr_length_checks_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_event_injection_instr_length_checks);
}

void
vmcs_ut::test_check_control_entry_msr_load_address()
{
    std::vector<struct control_flow_path> cfg;
    setup_check_control_entry_msr_load_address_paths(cfg);

    this->run_vmcs_test(cfg, &vmcs_intel_x64::check_control_entry_msr_load_address);
}
