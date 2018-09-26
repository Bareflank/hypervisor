//
// Bareflank Hypervisor
// Copyright (C) 2017 Assured Information Security, Inc.
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

#ifndef INTRINSICS_H
#define INTRINSICS_H

#include <bfarch.h>
#include <stdint.h>

inline uintptr_t g_rsdp = 0;

#ifdef BF_X64
#include <arch/x64/cache.h>
#include <arch/x64/cpuid.h>
#include <arch/x64/gdt.h>
#include <arch/x64/idt.h>
#include <arch/x64/misc.h>
#include <arch/x64/msrs.h>
#include <arch/x64/paging.h>
#include <arch/x64/pm.h>
#include <arch/x64/portio.h>
#include <arch/x64/rdtsc.h>
#include <arch/x64/rflags.h>
#include <arch/x64/srs.h>
#include <arch/x64/tlb.h>
#endif

#ifdef BF_INTEL_X64
#include <arch/intel_x64/apic/lapic.h>
#include <arch/intel_x64/apic/x2apic.h>
#include <arch/intel_x64/bit.h>
#include <arch/intel_x64/cpuid.h>
#include <arch/intel_x64/crs.h>
#include <arch/intel_x64/ept.h>
#include <arch/intel_x64/drs.h>
#include <arch/intel_x64/msrs.h>
#include <arch/intel_x64/pause.h>
#include <arch/intel_x64/vmx.h>
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
#include <arch/intel_x64/vmcs/debug.h>
#include <arch/intel_x64/vmcs/helpers.h>
#include <arch/intel_x64/vmcs/natural_width_control_fields.h>
#include <arch/intel_x64/vmcs/natural_width_guest_state_fields.h>
#include <arch/intel_x64/vmcs/natural_width_host_state_fields.h>
#include <arch/intel_x64/vmcs/natural_width_read_only_data_fields.h>
#include <arch/intel_x64/vtd/context_entry.h>
#include <arch/intel_x64/vtd/extended_context_entry.h>
#include <arch/intel_x64/vtd/extended_root_entry.h>
#include <arch/intel_x64/vtd/fault_record.h>
#include <arch/intel_x64/vtd/first_level_paging_entries.h>
#include <arch/intel_x64/vtd/irte.h>
#include <arch/intel_x64/vtd/pasid_entry.h>
#include <arch/intel_x64/vtd/pasid_state_entry.h>
#include <arch/intel_x64/vtd/pid.h>
#include <arch/intel_x64/vtd/root_entry.h>
#include <arch/intel_x64/vtd/second_level_paging_entries.h>
#endif

#ifdef BF_AARCH64
#error "unimplemented"
#endif

#endif
