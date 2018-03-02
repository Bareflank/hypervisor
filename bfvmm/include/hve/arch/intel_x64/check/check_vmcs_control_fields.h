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

#ifndef VMCS_INTEL_X64_CHECK_CONTROLS_H
#define VMCS_INTEL_X64_CHECK_CONTROLS_H

#include <intrinsics.h>

/// Intel x86_64 VMCS Check Controls
///
/// This namespace implements the control checks found in
/// section 26.2.1, Vol. 3 of the SDM.
///

namespace bfvmm
{
namespace intel_x64
{
namespace check
{

void control_reserved_properly_set(
    ::x64::msrs::field_type addr, ::x64::msrs::value_type ctls, const char *name);

void control_pin_based_ctls_reserved_properly_set();
void control_proc_based_ctls_reserved_properly_set();
void control_proc_based_ctls2_reserved_properly_set();
void control_cr3_count_less_then_4();
void control_io_bitmap_address_bits();
void control_msr_bitmap_address_bits();
void control_tpr_shadow_and_virtual_apic();
void control_nmi_exiting_and_virtual_nmi();
void control_virtual_nmi_and_nmi_window();
void control_virtual_apic_address_bits();
void control_x2apic_mode_and_virtual_apic_access();
void control_virtual_interrupt_and_external_interrupt();
void control_process_posted_interrupt_checks();
void control_vpid_checks();
void control_enable_ept_checks();
void control_enable_pml_checks();
void control_unrestricted_guests();
void control_enable_vm_functions();
void control_enable_vmcs_shadowing();
void control_enable_ept_violation_checks();
void control_vm_exit_ctls_reserved_properly_set();
void control_activate_and_save_preemption_timer_must_be_0();
void control_exit_msr_store_address();
void control_exit_msr_load_address();
void control_vm_entry_ctls_reserved_properly_set();
void control_event_injection_type_vector_checks();
void control_event_injection_delivery_ec_checks();
void control_event_injection_reserved_bits_checks();
void control_event_injection_ec_checks();
void control_event_injection_instr_length_checks();
void control_entry_msr_load_address();
void control_vm_exit_control_fields_all();

}
}
}

#endif
