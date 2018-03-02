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

#ifndef VMCS_INTEL_X64_DEBUG_H
#define VMCS_INTEL_X64_DEBUG_H

#include <arch/intel_x64/vmcs/16bit_control_fields.h>
#include <arch/intel_x64/vmcs/16bit_guest_state_fields.h>
#include <arch/intel_x64/vmcs/16bit_host_state_fields.h>
#include <arch/intel_x64/vmcs/32bit_control_fields.h>
#include <arch/intel_x64/vmcs/32bit_guest_state_fields.h>
#include <arch/intel_x64/vmcs/32bit_host_state_fields.h>
#include <arch/intel_x64/vmcs/32bit_read_only_data_fields.h>
#include <arch/intel_x64/vmcs/64bit_control_fields.h>
#include <arch/intel_x64/vmcs/64bit_guest_state_fields.h>
#include <arch/intel_x64/vmcs/64bit_host_state_fields.h>
#include <arch/intel_x64/vmcs/64bit_read_only_data_fields.h>
#include <arch/intel_x64/vmcs/natural_width_control_fields.h>
#include <arch/intel_x64/vmcs/natural_width_guest_state_fields.h>
#include <arch/intel_x64/vmcs/natural_width_host_state_fields.h>
#include <arch/intel_x64/vmcs/natural_width_read_only_data_fields.h>

// *INDENT-OFF*

namespace intel_x64
{
namespace vmcs
{

namespace debug
{
    inline void dump(int level = 0)
    {
        bfdebug_transaction(level, [&](std::string * msg) {
            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "16bit control fields", msg);
            bfdebug_brk3(level, msg);

            virtual_processor_identifier::dump(level, msg);
            posted_interrupt_notification_vector::dump(level, msg);
            eptp_index::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "16bit guest state fields", msg);
            bfdebug_brk3(level, msg);

            guest_es_selector::dump(level, msg);
            guest_cs_selector::dump(level, msg);
            guest_ss_selector::dump(level, msg);
            guest_ds_selector::dump(level, msg);
            guest_fs_selector::dump(level, msg);
            guest_gs_selector::dump(level, msg);
            guest_ldtr_selector::dump(level, msg);
            guest_tr_selector::dump(level, msg);
            guest_interrupt_status::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "16bit host state fields", msg);
            bfdebug_brk3(level, msg);

            host_es_selector::dump(level, msg);
            host_cs_selector::dump(level, msg);
            host_ss_selector::dump(level, msg);
            host_ds_selector::dump(level, msg);
            host_fs_selector::dump(level, msg);
            host_gs_selector::dump(level, msg);
            host_tr_selector::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "64bit control fields", msg);
            bfdebug_brk3(level, msg);

            address_of_io_bitmap_a::dump(level, msg);
            address_of_io_bitmap_b::dump(level, msg);
            address_of_msr_bitmap::dump(level, msg);
            vm_exit_msr_store_address::dump(level, msg);
            vm_exit_msr_load_address::dump(level, msg);
            vm_entry_msr_load_address::dump(level, msg);
            executive_vmcs_pointer::dump(level, msg);
            tsc_offset::dump(level, msg);
            virtual_apic_address::dump(level, msg);
            apic_access_address::dump(level, msg);
            posted_interrupt_descriptor_address::dump(level, msg);
            vm_function_controls::dump(level, msg);
            ept_pointer::dump(level, msg);
            eoi_exit_bitmap_0::dump(level, msg);
            eoi_exit_bitmap_1::dump(level, msg);
            eoi_exit_bitmap_2::dump(level, msg);
            eoi_exit_bitmap_3::dump(level, msg);
            eptp_list_address::dump(level, msg);
            vmread_bitmap_address::dump(level, msg);
            vmwrite_bitmap_address::dump(level, msg);
            virtualization_exception_information_address::dump(level, msg);
            xss_exiting_bitmap::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "64bit read-only data fields", msg);
            bfdebug_brk3(level, msg);

            guest_physical_address::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "64bit guest state fields", msg);
            bfdebug_brk3(level, msg);

            vmcs_link_pointer::dump(level, msg);
            guest_ia32_debugctl::dump(level, msg);
            guest_ia32_pat::dump(level, msg);
            guest_ia32_efer::dump(level, msg);
            guest_ia32_perf_global_ctrl::dump(level, msg);
            guest_pdpte0::dump(level, msg);
            guest_pdpte1::dump(level, msg);
            guest_pdpte2::dump(level, msg);
            guest_pdpte3::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "64bit host state fields", msg);
            bfdebug_brk3(level, msg);

            host_ia32_pat::dump(level, msg);
            host_ia32_efer::dump(level, msg);
            host_ia32_perf_global_ctrl::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "32bit control fields", msg);
            bfdebug_brk3(level, msg);

            pin_based_vm_execution_controls::dump(level, msg);
            primary_processor_based_vm_execution_controls::dump(level, msg);
            exception_bitmap::dump(level, msg);
            page_fault_error_code_mask::dump(level, msg);
            page_fault_error_code_match::dump(level, msg);
            cr3_target_count::dump(level, msg);
            vm_exit_controls::dump(level, msg);
            vm_exit_msr_store_count::dump(level, msg);
            vm_exit_msr_load_count::dump(level, msg);
            vm_entry_controls::dump(level, msg);
            vm_entry_msr_load_count::dump(level, msg);
            vm_entry_interruption_information::dump(level, msg);
            vm_entry_exception_error_code::dump(level, msg);
            vm_entry_instruction_length::dump(level, msg);
            tpr_threshold::dump(level, msg);
            secondary_processor_based_vm_execution_controls::dump(level, msg);
            ple_gap::dump(level, msg);
            ple_window::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "32bit read-only data fields", msg);
            bfdebug_brk3(level, msg);

            exit_reason::dump(level, msg);
            vm_exit_interruption_information::dump(level, msg);
            vm_exit_interruption_error_code::dump(level, msg);
            idt_vectoring_information::dump(level, msg);
            idt_vectoring_error_code::dump(level, msg);
            vm_exit_instruction_length::dump(level, msg);
            vm_exit_instruction_information::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "32bit guest state fields", msg);
            bfdebug_brk3(level, msg);

            guest_es_limit::dump(level, msg);
            guest_cs_limit::dump(level, msg);
            guest_ss_limit::dump(level, msg);
            guest_ds_limit::dump(level, msg);
            guest_fs_limit::dump(level, msg);
            guest_gs_limit::dump(level, msg);
            guest_ldtr_limit::dump(level, msg);
            guest_tr_limit::dump(level, msg);
            guest_gdtr_limit::dump(level, msg);
            guest_idtr_limit::dump(level, msg);
            guest_es_access_rights::dump(level, msg);
            guest_cs_access_rights::dump(level, msg);
            guest_ss_access_rights::dump(level, msg);
            guest_ds_access_rights::dump(level, msg);
            guest_fs_access_rights::dump(level, msg);
            guest_gs_access_rights::dump(level, msg);
            guest_ldtr_access_rights::dump(level, msg);
            guest_tr_access_rights::dump(level, msg);
            guest_interruptibility_state::dump(level, msg);
            guest_activity_state::dump(level, msg);
            guest_smbase::dump(level, msg);
            guest_ia32_sysenter_cs::dump(level, msg);
            vmx_preemption_timer_value::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "32bit host state fields", msg);
            bfdebug_brk3(level, msg);

            host_ia32_sysenter_cs::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "natural width control fields", msg);
            bfdebug_brk3(level, msg);

            cr0_guest_host_mask::dump(level, msg);
            cr4_guest_host_mask::dump(level, msg);
            cr0_read_shadow::dump(level, msg);
            cr4_read_shadow::dump(level, msg);
            cr3_target_value_0::dump(level, msg);
            cr3_target_value_1::dump(level, msg);
            cr3_target_value_2::dump(level, msg);
            cr3_target_value_3::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "natural width read-only data fields", msg);
            bfdebug_brk3(level, msg);

            exit_qualification::dump(level, msg);
            io_rcx::dump(level, msg);
            io_rsi::dump(level, msg);
            io_rdi::dump(level, msg);
            io_rip::dump(level, msg);
            guest_linear_address::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "natural width guest state fields", msg);
            bfdebug_brk3(level, msg);

            guest_cr0::dump(level, msg);
            guest_cr3::dump(level, msg);
            guest_cr4::dump(level, msg);
            guest_es_base::dump(level, msg);
            guest_cs_base::dump(level, msg);
            guest_ss_base::dump(level, msg);
            guest_ds_base::dump(level, msg);
            guest_fs_base::dump(level, msg);
            guest_gs_base::dump(level, msg);
            guest_ldtr_base::dump(level, msg);
            guest_tr_base::dump(level, msg);
            guest_gdtr_base::dump(level, msg);
            guest_idtr_base::dump(level, msg);
            guest_dr7::dump(level, msg);
            guest_rsp::dump(level, msg);
            guest_rip::dump(level, msg);
            guest_rflags::dump(level, msg);
            guest_pending_debug_exceptions::dump(level, msg);
            guest_ia32_sysenter_esp::dump(level, msg);
            guest_ia32_sysenter_eip::dump(level, msg);

            bfdebug_lnbr(level, msg);
            bfdebug_info(level, "natural width host state fields", msg);
            bfdebug_brk3(level, msg);

            host_cr0::dump(level, msg);
            host_cr3::dump(level, msg);
            host_cr4::dump(level, msg);
            host_fs_base::dump(level, msg);
            host_gs_base::dump(level, msg);
            host_tr_base::dump(level, msg);
            host_gdtr_base::dump(level, msg);
            host_idtr_base::dump(level, msg);
            host_ia32_sysenter_esp::dump(level, msg);
            host_ia32_sysenter_eip::dump(level, msg);
            host_rsp::dump(level, msg);
            host_rip::dump(level, msg);
        });
    }
}

}
}

// *INDENT-ON*

#endif
