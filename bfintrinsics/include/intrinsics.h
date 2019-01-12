//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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
#include <arch/intel_x64/barrier.h>
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

namespace vmcs_n = ::intel_x64::vmcs;

#endif

#ifdef BF_AARCH64
#error "unimplemented"
#endif

#endif
