//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#ifndef INTRINSICS_VMCS_INTEL_X64_H
#define INTRINSICS_VMCS_INTEL_X64_H

#include <intrinsics/x86/intel/vmcs/16bit_control_fields.h>
#include <intrinsics/x86/intel/vmcs/16bit_guest_state_fields.h>
#include <intrinsics/x86/intel/vmcs/16bit_host_state_fields.h>

#include <intrinsics/x86/intel/vmcs/32bit_control_fields.h>
#include <intrinsics/x86/intel/vmcs/32bit_guest_state_fields.h>
#include <intrinsics/x86/intel/vmcs/32bit_host_state_field.h>
#include <intrinsics/x86/intel/vmcs/32bit_read_only_data_fields.h>

#include <intrinsics/x86/intel/vmcs/64bit_control_fields.h>
#include <intrinsics/x86/intel/vmcs/64bit_guest_state_fields.h>
#include <intrinsics/x86/intel/vmcs/64bit_host_state_fields.h>
#include <intrinsics/x86/intel/vmcs/64bit_read_only_data_fields.h>

#include <intrinsics/x86/intel/vmcs/natural_width_control_fields.h>
#include <intrinsics/x86/intel/vmcs/natural_width_guest_state_fields.h>
#include <intrinsics/x86/intel/vmcs/natural_width_host_state_fields.h>
#include <intrinsics/x86/intel/vmcs/natural_width_read_only_data_fields.h>

#include <intrinsics/x86/intel/vmcs/check.h>
#include <intrinsics/x86/intel/vmcs/debug.h>

#endif
