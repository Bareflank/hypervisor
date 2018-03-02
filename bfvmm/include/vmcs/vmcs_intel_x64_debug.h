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

#ifndef VMCS_INTEL_X64_DEBUG_H
#define VMCS_INTEL_X64_DEBUG_H

#include <vmcs/vmcs_intel_x64_16bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_16bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_16bit_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_host_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_host_state_field.h>
#include <vmcs/vmcs_intel_x64_natural_width_control_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_host_state_fields.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace debug
{
    inline void dump();
    inline void dump_16bit_control_fields();
    inline void dump_16bit_guest_state_fields();
    inline void dump_16bit_host_state_fields();
    inline void dump_64bit_control_fields();
    inline void dump_64bit_read_only_data_field();
    inline void dump_64bit_guest_state_fields();
    inline void dump_64bit_host_state_fields();
    inline void dump_32bit_control_fields();
    inline void dump_32bit_read_only_data_fields();
    inline void dump_32bit_guest_state_fields();
    inline void dump_32bit_host_state_field();
    inline void dump_natural_width_control_fields();
    inline void dump_natural_width_read_only_data_fields();
    inline void dump_natural_width_guest_state_fields();
    inline void dump_natural_width_host_state_fields();
    inline void dump_vmx_controls();
    inline void dump_pin_based_vm_execution_controls();
    inline void dump_primary_processor_based_vm_execution_controls();
    inline void dump_secondary_processor_based_vm_execution_controls();
    inline void dump_vm_exit_control_fields();
    inline void dump_vm_entry_control_fields();

    inline void dump_vmcs_field(vmcs::field_type addr, const char *name, bool exists);
    inline void dump_vm_control(const char *name, bool is_set);

    inline void dump()
    {
        bfdebug << "----------------------------------------" << bfendl;
        bfdebug << "- VMCS Dump                            -" << bfendl;
        bfdebug << "----------------------------------------" << bfendl;

        dump_16bit_control_fields();
        dump_16bit_guest_state_fields();
        dump_16bit_host_state_fields();
        dump_64bit_control_fields();
        dump_64bit_read_only_data_field();
        dump_64bit_guest_state_fields();
        dump_64bit_host_state_fields();
        dump_32bit_control_fields();
        dump_32bit_read_only_data_fields();
        dump_32bit_guest_state_fields();
        dump_32bit_host_state_field();
        dump_natural_width_control_fields();
        dump_natural_width_read_only_data_fields();
        dump_natural_width_guest_state_fields();
        dump_natural_width_host_state_fields();
        dump_vmx_controls();

        bfdebug << bfendl;
    }

    inline void dump_16bit_control_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(virtual_processor_identifier::addr,
                        virtual_processor_identifier::name,
                        virtual_processor_identifier::exists());

        dump_vmcs_field(posted_interrupt_notification_vector::addr,
                        posted_interrupt_notification_vector::name,
                        posted_interrupt_notification_vector::exists());

        dump_vmcs_field(eptp_index::addr,
                        eptp_index::name,
                        eptp_index::exists());
    }

    inline void dump_16bit_guest_state_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(guest_es_selector::addr,
                        guest_es_selector::name,
                        guest_es_selector::exists());

        dump_vmcs_field(guest_cs_selector::addr,
                        guest_cs_selector::name,
                        guest_cs_selector::exists());

        dump_vmcs_field(guest_ss_selector::addr,
                        guest_ss_selector::name,
                        guest_ss_selector::exists());

        dump_vmcs_field(guest_ds_selector::addr,
                        guest_ds_selector::name,
                        guest_ds_selector::exists());

        dump_vmcs_field(guest_fs_selector::addr,
                        guest_fs_selector::name,
                        guest_fs_selector::exists());

        dump_vmcs_field(guest_gs_selector::addr,
                        guest_gs_selector::name,
                        guest_gs_selector::exists());

        dump_vmcs_field(guest_ldtr_selector::addr,
                        guest_ldtr_selector::name,
                        guest_ldtr_selector::exists());

        dump_vmcs_field(guest_tr_selector::addr,
                        guest_tr_selector::name,
                        guest_tr_selector::exists());

        dump_vmcs_field(guest_interrupt_status::addr,
                        guest_interrupt_status::name,
                        guest_interrupt_status::exists());
    }

    inline void dump_16bit_host_state_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(host_es_selector::addr,
                        host_es_selector::name,
                        host_es_selector::exists());

        dump_vmcs_field(host_cs_selector::addr,
                        host_cs_selector::name,
                        host_cs_selector::exists());

        dump_vmcs_field(host_ss_selector::addr,
                        host_ss_selector::name,
                        host_ss_selector::exists());

        dump_vmcs_field(host_ds_selector::addr,
                        host_ds_selector::name,
                        host_ds_selector::exists());

        dump_vmcs_field(host_fs_selector::addr,
                        host_fs_selector::name,
                        host_fs_selector::exists());

        dump_vmcs_field(host_gs_selector::addr,
                        host_gs_selector::name,
                        host_gs_selector::exists());

        dump_vmcs_field(host_tr_selector::addr,
                        host_tr_selector::name,
                        host_tr_selector::exists());
    }


    inline void dump_64bit_control_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(address_of_io_bitmap_a::addr,
                        address_of_io_bitmap_a::name,
                        address_of_io_bitmap_a::exists());

        dump_vmcs_field(address_of_io_bitmap_b::addr,
                        address_of_io_bitmap_b::name,
                        address_of_io_bitmap_b::exists());

        dump_vmcs_field(address_of_msr_bitmap::addr,
                        address_of_msr_bitmap::name,
                        address_of_msr_bitmap::exists());

        dump_vmcs_field(vm_exit_msr_store_address::addr,
                        vm_exit_msr_store_address::name,
                        vm_exit_msr_store_address::exists());

        dump_vmcs_field(vm_exit_msr_load_address::addr,
                        vm_exit_msr_load_address::name,
                        vm_exit_msr_load_address::exists());

        dump_vmcs_field(vm_entry_msr_load_address::addr,
                        vm_entry_msr_load_address::name,
                        vm_entry_msr_load_address::exists());

        dump_vmcs_field(executive_vmcs_pointer::addr,
                        executive_vmcs_pointer::name,
                        executive_vmcs_pointer::exists());

        dump_vmcs_field(tsc_offset::addr,
                        tsc_offset::name,
                        tsc_offset::exists());

        dump_vmcs_field(virtual_apic_address::addr,
                        virtual_apic_address::name,
                        virtual_apic_address::exists());

        dump_vmcs_field(apic_access_address::addr,
                        apic_access_address::name,
                        apic_access_address::exists());

        dump_vmcs_field(posted_interrupt_descriptor_address::addr,
                        posted_interrupt_descriptor_address::name,
                        posted_interrupt_descriptor_address::exists());

        dump_vmcs_field(vm_function_controls::addr,
                        vm_function_controls::name,
                        vm_function_controls::exists());

        dump_vmcs_field(ept_pointer::addr,
                        ept_pointer::name,
                        ept_pointer::exists());

        dump_vmcs_field(eoi_exit_bitmap_0::addr,
                        eoi_exit_bitmap_0::name,
                        eoi_exit_bitmap_0::exists());

        dump_vmcs_field(eoi_exit_bitmap_1::addr,
                        eoi_exit_bitmap_1::name,
                        eoi_exit_bitmap_1::exists());

        dump_vmcs_field(eoi_exit_bitmap_2::addr,
                        eoi_exit_bitmap_2::name,
                        eoi_exit_bitmap_2::exists());

        dump_vmcs_field(eoi_exit_bitmap_3::addr,
                        eoi_exit_bitmap_3::name,
                        eoi_exit_bitmap_3::exists());

        dump_vmcs_field(eptp_list_address::addr,
                        eptp_list_address::name,
                        eptp_list_address::exists());

        dump_vmcs_field(vmread_bitmap_address::addr,
                        vmread_bitmap_address::name,
                        vmread_bitmap_address::exists());

        dump_vmcs_field(vmwrite_bitmap_address::addr,
                        vmwrite_bitmap_address::name,
                        vmwrite_bitmap_address::exists());

        dump_vmcs_field(virtualization_exception_information_address::addr,
                        virtualization_exception_information_address::name,
                        virtualization_exception_information_address::exists());

        dump_vmcs_field(xss_exiting_bitmap::addr,
                        xss_exiting_bitmap::name,
                        xss_exiting_bitmap::exists());
    }

    inline void dump_64bit_read_only_data_field()
    {
        bfdebug << bfendl;

        dump_vmcs_field(guest_physical_address::addr,
                        guest_physical_address::name,
                        guest_physical_address::exists());
    }

    inline void dump_64bit_guest_state_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(vmcs_link_pointer::addr,
                        vmcs_link_pointer::name,
                        vmcs_link_pointer::exists());

        dump_vmcs_field(guest_ia32_debugctl::addr,
                        guest_ia32_debugctl::name,
                        guest_ia32_debugctl::exists());

        dump_vmcs_field(guest_ia32_pat::addr,
                        guest_ia32_pat::name,
                        guest_ia32_pat::exists());

        dump_vmcs_field(guest_ia32_efer::addr,
                        guest_ia32_efer::name,
                        guest_ia32_efer::exists());

        dump_vmcs_field(guest_ia32_perf_global_ctrl::addr,
                        guest_ia32_perf_global_ctrl::name,
                        guest_ia32_perf_global_ctrl::exists());

        dump_vmcs_field(guest_pdpte0::addr,
                        guest_pdpte0::name,
                        guest_pdpte0::exists());

        dump_vmcs_field(guest_pdpte1::addr,
                        guest_pdpte1::name,
                        guest_pdpte1::exists());

        dump_vmcs_field(guest_pdpte2::addr,
                        guest_pdpte2::name,
                        guest_pdpte2::exists());

        dump_vmcs_field(guest_pdpte3::addr,
                        guest_pdpte3::name,
                        guest_pdpte3::exists());
    }

    inline void dump_64bit_host_state_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(host_ia32_pat::addr,
                        host_ia32_pat::name,
                        host_ia32_pat::exists());

        dump_vmcs_field(host_ia32_efer::addr,
                        host_ia32_efer::name,
                        host_ia32_efer::exists());

        dump_vmcs_field(host_ia32_perf_global_ctrl::addr,
                        host_ia32_perf_global_ctrl::name,
                        host_ia32_perf_global_ctrl::exists());
    }

    inline void dump_32bit_control_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(pin_based_vm_execution_controls::addr,
                        pin_based_vm_execution_controls::name,
                        pin_based_vm_execution_controls::exists());

        dump_vmcs_field(primary_processor_based_vm_execution_controls::addr,
                        primary_processor_based_vm_execution_controls::name,
                        primary_processor_based_vm_execution_controls::exists());

        dump_vmcs_field(exception_bitmap::addr,
                        exception_bitmap::name,
                        exception_bitmap::exists());

        dump_vmcs_field(page_fault_error_code_mask::addr,
                        page_fault_error_code_mask::name,
                        page_fault_error_code_mask::exists());

        dump_vmcs_field(page_fault_error_code_match::addr,
                        page_fault_error_code_match::name,
                        page_fault_error_code_match::exists());

        dump_vmcs_field(cr3_target_count::addr,
                        cr3_target_count::name,
                        cr3_target_count::exists());

        dump_vmcs_field(vm_exit_controls::addr,
                        vm_exit_controls::name,
                        vm_exit_controls::exists());

        dump_vmcs_field(vm_exit_msr_store_count::addr,
                        vm_exit_msr_store_count::name,
                        vm_exit_msr_store_count::exists());

        dump_vmcs_field(vm_exit_msr_load_count::addr,
                        vm_exit_msr_load_count::name,
                        vm_exit_msr_load_count::exists());

        dump_vmcs_field(vm_entry_controls::addr,
                        vm_entry_controls::name,
                        vm_entry_controls::exists());

        dump_vmcs_field(vm_entry_msr_load_count::addr,
                        vm_entry_msr_load_count::name,
                        vm_entry_msr_load_count::exists());

        dump_vmcs_field(vm_entry_interruption_information_field::addr,
                        vm_entry_interruption_information_field::name,
                        vm_entry_interruption_information_field::exists());

        dump_vmcs_field(vm_entry_exception_error_code::addr,
                        vm_entry_exception_error_code::name,
                        vm_entry_exception_error_code::exists());

        dump_vmcs_field(vm_entry_instruction_length::addr,
                        vm_entry_instruction_length::name,
                        vm_entry_instruction_length::exists());

        dump_vmcs_field(tpr_threshold::addr,
                        tpr_threshold::name,
                        tpr_threshold::exists());

        dump_vmcs_field(secondary_processor_based_vm_execution_controls::addr,
                        secondary_processor_based_vm_execution_controls::name,
                        secondary_processor_based_vm_execution_controls::exists());

        dump_vmcs_field(ple_gap::addr,
                        ple_gap::name,
                        ple_gap::exists());

        dump_vmcs_field(ple_window::addr,
                        ple_window::name,
                        ple_window::exists());

    }

    inline void dump_32bit_read_only_data_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(vm_instruction_error::addr,
                        vm_instruction_error::name,
                        vm_instruction_error::exists());

        dump_vmcs_field(exit_reason::addr,
                        exit_reason::name,
                        exit_reason::exists());

        dump_vmcs_field(vm_exit_interruption_information::addr,
                        vm_exit_interruption_information::name,
                        vm_exit_interruption_information::exists());

        dump_vmcs_field(vm_exit_interruption_error_code::addr,
                        vm_exit_interruption_error_code::name,
                        vm_exit_interruption_error_code::exists());

        dump_vmcs_field(idt_vectoring_information::addr,
                        idt_vectoring_information::name,
                        idt_vectoring_information::exists());

        dump_vmcs_field(idt_vectoring_error_code::addr,
                        idt_vectoring_error_code::name,
                        idt_vectoring_error_code::exists());

        dump_vmcs_field(vm_exit_instruction_length::addr,
                        vm_exit_instruction_length::name,
                        vm_exit_instruction_length::exists());

        dump_vmcs_field(vm_exit_instruction_information::addr,
                        vm_exit_instruction_information::name,
                        vm_exit_instruction_information::exists());
    }

    inline void dump_32bit_guest_state_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(guest_es_limit::addr,
                        guest_es_limit::name,
                        guest_es_limit::exists());

        dump_vmcs_field(guest_cs_limit::addr,
                        guest_cs_limit::name,
                        guest_cs_limit::exists());

        dump_vmcs_field(guest_ss_limit::addr,
                        guest_ss_limit::name,
                        guest_ss_limit::exists());

        dump_vmcs_field(guest_ds_limit::addr,
                        guest_ds_limit::name,
                        guest_ds_limit::exists());

        dump_vmcs_field(guest_fs_limit::addr,
                        guest_fs_limit::name,
                        guest_fs_limit::exists());

        dump_vmcs_field(guest_gs_limit::addr,
                        guest_gs_limit::name,
                        guest_gs_limit::exists());

        dump_vmcs_field(guest_ldtr_limit::addr,
                        guest_ldtr_limit::name,
                        guest_ldtr_limit::exists());

        dump_vmcs_field(guest_tr_limit::addr,
                        guest_tr_limit::name,
                        guest_tr_limit::exists());

        dump_vmcs_field(guest_gdtr_limit::addr,
                        guest_gdtr_limit::name,
                        guest_gdtr_limit::exists());

        dump_vmcs_field(guest_idtr_limit::addr,
                        guest_idtr_limit::name,
                        guest_idtr_limit::exists());

        dump_vmcs_field(guest_es_access_rights::addr,
                        guest_es_access_rights::name,
                        guest_es_access_rights::exists());

        dump_vmcs_field(guest_cs_access_rights::addr,
                        guest_cs_access_rights::name,
                        guest_cs_access_rights::exists());

        dump_vmcs_field(guest_ss_access_rights::addr,
                        guest_ss_access_rights::name,
                        guest_ss_access_rights::exists());

        dump_vmcs_field(guest_ds_access_rights::addr,
                        guest_ds_access_rights::name,
                        guest_ds_access_rights::exists());

        dump_vmcs_field(guest_fs_access_rights::addr,
                        guest_fs_access_rights::name,
                        guest_fs_access_rights::exists());

        dump_vmcs_field(guest_gs_access_rights::addr,
                        guest_gs_access_rights::name,
                        guest_gs_access_rights::exists());

        dump_vmcs_field(guest_ldtr_access_rights::addr,
                        guest_ldtr_access_rights::name,
                        guest_ldtr_access_rights::exists());

        dump_vmcs_field(guest_tr_access_rights::addr,
                        guest_tr_access_rights::name,
                        guest_tr_access_rights::exists());

        dump_vmcs_field(guest_interruptibility_state::addr,
                        guest_interruptibility_state::name,
                        guest_interruptibility_state::exists());

        dump_vmcs_field(guest_activity_state::addr,
                        guest_activity_state::name,
                        guest_activity_state::exists());

        dump_vmcs_field(guest_smbase::addr,
                        guest_smbase::name,
                        guest_smbase::exists());

        dump_vmcs_field(guest_ia32_sysenter_cs::addr,
                        guest_ia32_sysenter_cs::name,
                        guest_ia32_sysenter_cs::exists());

        dump_vmcs_field(vmx_preemption_timer_value::addr,
                        vmx_preemption_timer_value::name,
                        vmx_preemption_timer_value::exists());
    }

    inline void dump_32bit_host_state_field()
    {
        bfdebug << bfendl;

        dump_vmcs_field(host_ia32_sysenter_cs::addr,
                        host_ia32_sysenter_cs::name,
                        host_ia32_sysenter_cs::exists());
    }

    inline void dump_natural_width_control_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(cr0_guest_host_mask::addr,
                        cr0_guest_host_mask::name,
                        cr0_guest_host_mask::exists());

        dump_vmcs_field(cr4_guest_host_mask::addr,
                        cr4_guest_host_mask::name,
                        cr4_guest_host_mask::exists());

        dump_vmcs_field(cr0_read_shadow::addr,
                        cr0_read_shadow::name,
                        cr0_read_shadow::exists());

        dump_vmcs_field(cr4_read_shadow::addr,
                        cr4_read_shadow::name,
                        cr4_read_shadow::exists());

        dump_vmcs_field(cr3_target_value_0::addr,
                        cr3_target_value_0::name,
                        cr3_target_value_0::exists());

        dump_vmcs_field(cr3_target_value_1::addr,
                        cr3_target_value_1::name,
                        cr3_target_value_1::exists());

        dump_vmcs_field(cr3_target_value_2::addr,
                        cr3_target_value_2::name,
                        cr3_target_value_2::exists());

        dump_vmcs_field(cr3_target_value_3::addr,
                        cr3_target_value_3::name,
                        cr3_target_value_3::exists());
    }

    inline void dump_natural_width_read_only_data_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(exit_qualification::addr,
                        exit_qualification::name,
                        exit_qualification::exists());

        dump_vmcs_field(io_rcx::addr,
                        io_rcx::name,
                        io_rcx::exists());

        dump_vmcs_field(io_rsi::addr,
                        io_rsi::name,
                        io_rsi::exists());

        dump_vmcs_field(io_rdi::addr,
                        io_rdi::name,
                        io_rdi::exists());

        dump_vmcs_field(io_rip::addr,
                        io_rip::name,
                        io_rip::exists());

        dump_vmcs_field(guest_linear_address::addr,
                        guest_linear_address::name,
                        guest_linear_address::exists());
    }

    inline void dump_natural_width_guest_state_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(guest_cr0::addr,
                        guest_cr0::name,
                        guest_cr0::exists());

        dump_vmcs_field(guest_cr3::addr,
                        guest_cr3::name,
                        guest_cr3::exists());

        dump_vmcs_field(guest_cr4::addr,
                        guest_cr4::name,
                        guest_cr4::exists());

        dump_vmcs_field(guest_es_base::addr,
                        guest_es_base::name,
                        guest_es_base::exists());

        dump_vmcs_field(guest_cs_base::addr,
                        guest_cs_base::name,
                        guest_cs_base::exists());

        dump_vmcs_field(guest_ss_base::addr,
                        guest_ss_base::name,
                        guest_ss_base::exists());

        dump_vmcs_field(guest_ds_base::addr,
                        guest_ds_base::name,
                        guest_ds_base::exists());

        dump_vmcs_field(guest_fs_base::addr,
                        guest_fs_base::name,
                        guest_fs_base::exists());

        dump_vmcs_field(guest_gs_base::addr,
                        guest_gs_base::name,
                        guest_gs_base::exists());

        dump_vmcs_field(guest_ldtr_base::addr,
                        guest_ldtr_base::name,
                        guest_ldtr_base::exists());

        dump_vmcs_field(guest_tr_base::addr,
                        guest_tr_base::name,
                        guest_tr_base::exists());

        dump_vmcs_field(guest_gdtr_base::addr,
                        guest_gdtr_base::name,
                        guest_gdtr_base::exists());

        dump_vmcs_field(guest_idtr_base::addr,
                        guest_idtr_base::name,
                        guest_idtr_base::exists());

        dump_vmcs_field(guest_dr7::addr,
                        guest_dr7::name,
                        guest_dr7::exists());

        dump_vmcs_field(guest_rsp::addr,
                        guest_rsp::name,
                        guest_rsp::exists());

        dump_vmcs_field(guest_rip::addr,
                        guest_rip::name,
                        guest_rip::exists());

        dump_vmcs_field(guest_rflags::addr,
                        guest_rflags::name,
                        guest_rflags::exists());

        dump_vmcs_field(guest_pending_debug_exceptions::addr,
                        guest_pending_debug_exceptions::name,
                        guest_pending_debug_exceptions::exists());

        dump_vmcs_field(guest_ia32_sysenter_esp::addr,
                        guest_ia32_sysenter_esp::name,
                        guest_ia32_sysenter_esp::exists());

        dump_vmcs_field(guest_ia32_sysenter_eip::addr,
                        guest_ia32_sysenter_eip::name,
                        guest_ia32_sysenter_eip::exists());
    }

    inline void dump_natural_width_host_state_fields()
    {
        bfdebug << bfendl;

        dump_vmcs_field(host_cr0::addr,
                        host_cr0::name,
                        host_cr0::exists());

        dump_vmcs_field(host_cr3::addr,
                        host_cr3::name,
                        host_cr3::exists());

        dump_vmcs_field(host_cr4::addr,
                        host_cr4::name,
                        host_cr4::exists());

        dump_vmcs_field(host_fs_base::addr,
                        host_fs_base::name,
                        host_fs_base::exists());

        dump_vmcs_field(host_gs_base::addr,
                        host_gs_base::name,
                        host_gs_base::exists());

        dump_vmcs_field(host_tr_base::addr,
                        host_tr_base::name,
                        host_tr_base::exists());

        dump_vmcs_field(host_gdtr_base::addr,
                        host_gdtr_base::name,
                        host_gdtr_base::exists());

        dump_vmcs_field(host_idtr_base::addr,
                        host_idtr_base::name,
                        host_idtr_base::exists());

        dump_vmcs_field(host_ia32_sysenter_esp::addr,
                        host_ia32_sysenter_esp::name,
                        host_ia32_sysenter_esp::exists());

        dump_vmcs_field(host_ia32_sysenter_eip::addr,
                        host_ia32_sysenter_eip::name,
                        host_ia32_sysenter_eip::exists());

        dump_vmcs_field(host_rsp::addr,
                        host_rsp::name,
                        host_rsp::exists());

        dump_vmcs_field(host_rip::addr,
                        host_rip::name,
                        host_rip::exists());
    }

    inline void dump_vmx_controls()
    {
        bfdebug << bfendl;

        dump_pin_based_vm_execution_controls();
        dump_primary_processor_based_vm_execution_controls();
        dump_secondary_processor_based_vm_execution_controls();
        dump_vm_exit_control_fields();
        dump_vm_entry_control_fields();
    }

    inline void dump_pin_based_vm_execution_controls()
    {
        bfdebug << "vmcs::pin_based_vm_execution_controls enabled flags:" << bfendl;

        dump_vm_control(pin_based_vm_execution_controls::external_interrupt_exiting::name,
                        pin_based_vm_execution_controls::external_interrupt_exiting::is_enabled());

        dump_vm_control(pin_based_vm_execution_controls::nmi_exiting::name,
                        pin_based_vm_execution_controls::nmi_exiting::is_enabled());

        dump_vm_control(pin_based_vm_execution_controls::virtual_nmis::name,
                        pin_based_vm_execution_controls::virtual_nmis::is_enabled());

        dump_vm_control(pin_based_vm_execution_controls::activate_vmx_preemption_timer::name,
                        pin_based_vm_execution_controls::activate_vmx_preemption_timer::is_enabled());

        dump_vm_control(pin_based_vm_execution_controls::process_posted_interrupts::name,
                        pin_based_vm_execution_controls::process_posted_interrupts::is_enabled());

        bfdebug << bfendl;
    }

    inline void dump_primary_processor_based_vm_execution_controls()
    {
        bfdebug << "vmcs::primary_processor_based_vm_execution_controls enabled flags:" << bfendl;

        dump_vm_control(primary_processor_based_vm_execution_controls::interrupt_window_exiting::name,
                        primary_processor_based_vm_execution_controls::interrupt_window_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::use_tsc_offsetting::name,
                        primary_processor_based_vm_execution_controls::use_tsc_offsetting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::hlt_exiting::name,
                        primary_processor_based_vm_execution_controls::hlt_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::invlpg_exiting::name,
                        primary_processor_based_vm_execution_controls::invlpg_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::mwait_exiting::name,
                        primary_processor_based_vm_execution_controls::mwait_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::rdpmc_exiting::name,
                        primary_processor_based_vm_execution_controls::rdpmc_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::rdtsc_exiting::name,
                        primary_processor_based_vm_execution_controls::rdtsc_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::cr3_load_exiting::name,
                        primary_processor_based_vm_execution_controls::cr3_load_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::cr3_store_exiting::name,
                        primary_processor_based_vm_execution_controls::cr3_store_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::cr8_load_exiting::name,
                        primary_processor_based_vm_execution_controls::cr8_load_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::cr8_store_exiting::name,
                        primary_processor_based_vm_execution_controls::cr8_store_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::use_tpr_shadow::name,
                        primary_processor_based_vm_execution_controls::use_tpr_shadow::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::nmi_window_exiting::name,
                        primary_processor_based_vm_execution_controls::nmi_window_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::mov_dr_exiting::name,
                        primary_processor_based_vm_execution_controls::mov_dr_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::unconditional_io_exiting::name,
                        primary_processor_based_vm_execution_controls::unconditional_io_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::use_io_bitmaps::name,
                        primary_processor_based_vm_execution_controls::use_io_bitmaps::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::monitor_trap_flag::name,
                        primary_processor_based_vm_execution_controls::monitor_trap_flag::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::use_msr_bitmap::name,
                        primary_processor_based_vm_execution_controls::use_msr_bitmap::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::monitor_exiting::name,
                        primary_processor_based_vm_execution_controls::monitor_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::pause_exiting::name,
                        primary_processor_based_vm_execution_controls::pause_exiting::is_enabled());

        dump_vm_control(primary_processor_based_vm_execution_controls::activate_secondary_controls::name,
                        primary_processor_based_vm_execution_controls::activate_secondary_controls::is_enabled());

        bfdebug << bfendl;
    }

    inline void dump_secondary_processor_based_vm_execution_controls()
    {
        bfdebug << "vmcs::secondary_processor_based_vm_execution_controls enabled flags:" << bfendl;

        if (!vmcs::secondary_processor_based_vm_execution_controls::exists())
        {
            bfinfo << "doesn't exist" << bfendl;
            return;
        }

        dump_vm_control(secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::name,
                        secondary_processor_based_vm_execution_controls::virtualize_apic_accesses::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::enable_ept::name,
                        secondary_processor_based_vm_execution_controls::enable_ept::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::descriptor_table_exiting::name,
                        secondary_processor_based_vm_execution_controls::descriptor_table_exiting::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::enable_rdtscp::name,
                        secondary_processor_based_vm_execution_controls::enable_rdtscp::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::name,
                        secondary_processor_based_vm_execution_controls::virtualize_x2apic_mode::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::enable_vpid::name,
                        secondary_processor_based_vm_execution_controls::enable_vpid::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::wbinvd_exiting::name,
                        secondary_processor_based_vm_execution_controls::wbinvd_exiting::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::unrestricted_guest::name,
                        secondary_processor_based_vm_execution_controls::unrestricted_guest::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::apic_register_virtualization::name,
                        secondary_processor_based_vm_execution_controls::apic_register_virtualization::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::name,
                        secondary_processor_based_vm_execution_controls::virtual_interrupt_delivery::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::pause_loop_exiting::name,
                        secondary_processor_based_vm_execution_controls::pause_loop_exiting::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::rdrand_exiting::name,
                        secondary_processor_based_vm_execution_controls::rdrand_exiting::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::enable_invpcid::name,
                        secondary_processor_based_vm_execution_controls::enable_invpcid::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::enable_vm_functions::name,
                        secondary_processor_based_vm_execution_controls::enable_vm_functions::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::vmcs_shadowing::name,
                        secondary_processor_based_vm_execution_controls::vmcs_shadowing::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::rdseed_exiting::name,
                        secondary_processor_based_vm_execution_controls::rdseed_exiting::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::ept_violation_ve::name,
                        secondary_processor_based_vm_execution_controls::ept_violation_ve::is_enabled());

        dump_vm_control(secondary_processor_based_vm_execution_controls::enable_xsaves_xrstors::name,
                        secondary_processor_based_vm_execution_controls::enable_xsaves_xrstors::is_enabled());

        bfdebug << bfendl;
    }

    inline void dump_vm_exit_control_fields()
    {
        bfdebug << "vmcs::vm_exit_controls enabled flags:" << bfendl;

        dump_vm_control(vm_exit_controls::save_debug_controls::name,
                        vm_exit_controls::save_debug_controls::is_enabled());

        dump_vm_control(vm_exit_controls::host_address_space_size::name,
                        vm_exit_controls::host_address_space_size::is_enabled());

        dump_vm_control(vm_exit_controls::load_ia32_perf_global_ctrl::name,
                        vm_exit_controls::load_ia32_perf_global_ctrl::is_enabled());

        dump_vm_control(vm_exit_controls::acknowledge_interrupt_on_exit::name,
                        vm_exit_controls::acknowledge_interrupt_on_exit::is_enabled());

        dump_vm_control(vm_exit_controls::save_ia32_pat::name,
                        vm_exit_controls::save_ia32_pat::is_enabled());

        dump_vm_control(vm_exit_controls::load_ia32_pat::name,
                        vm_exit_controls::load_ia32_pat::is_enabled());

        dump_vm_control(vm_exit_controls::save_ia32_efer::name,
                        vm_exit_controls::save_ia32_efer::is_enabled());

        dump_vm_control(vm_exit_controls::load_ia32_efer::name,
                        vm_exit_controls::load_ia32_efer::is_enabled());

        dump_vm_control(vm_exit_controls::save_vmx_preemption_timer_value::name,
                        vm_exit_controls::save_vmx_preemption_timer_value::is_enabled());

        bfdebug << bfendl;
    }

    inline void dump_vm_entry_control_fields()
    {
        bfdebug << "vmcs::vm_entry_controls enabled flags:" << bfendl;

        dump_vm_control(vm_entry_controls::load_debug_controls::name,
                        vm_entry_controls::load_debug_controls::is_enabled());

        dump_vm_control(vm_entry_controls::ia_32e_mode_guest::name,
                        vm_entry_controls::ia_32e_mode_guest::is_enabled());

        dump_vm_control(vm_entry_controls::entry_to_smm::name,
                        vm_entry_controls::entry_to_smm::is_enabled());

        dump_vm_control(vm_entry_controls::deactivate_dual_monitor_treatment::name,
                        vm_entry_controls::deactivate_dual_monitor_treatment::is_enabled());

        dump_vm_control(vm_entry_controls::load_ia32_perf_global_ctrl::name,
                        vm_entry_controls::load_ia32_perf_global_ctrl::is_enabled());

        dump_vm_control(vm_entry_controls::load_ia32_pat::name,
                        vm_entry_controls::load_ia32_pat::is_enabled());

        dump_vm_control(vm_entry_controls::load_ia32_efer::name,
                        vm_entry_controls::load_ia32_efer::is_enabled());

        bfdebug << bfendl;
    }

    inline void
    dump_vmcs_field(vmcs::field_type addr, const char *name, bool exists)
    {
        bfdebug << "vmcs::" << name << ": ";

        if (!exists)
            bfinfo << "doesn't exist" << bfendl;
        else
            bfinfo << view_as_pointer(vm::read(addr, name)) << bfendl;
    }

    inline void dump_vm_control(const char *name, bool is_set)
    {
        if (is_set)
            bfdebug << "    - " << name << bfendl;
    }
}
}
}

// *INDENT-ON*

#endif
