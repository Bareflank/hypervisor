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

#ifndef VMCS_INTEL_X64_CHECKS
#define VMCS_INTEL_X64_CHECKS

#define verify_supported(a,b) \
    if ((m_intrinsics->read_msr(a) & (b << 32)) == 0) \
        throw hardware_unsupported(#b);

#define pin_enabled(a,b) \
    ((a & b) != 0) \
    { \
        verify_supported(IA32_VMX_PINBASED_CTLS_MSR,b); \
    } \
    if ((a & b) != 0)

#define pin_disabled(a,b) \
    ((a & b) != 0) \
    { \
        verify_supported(IA32_VMX_PINBASED_CTLS_MSR,b); \
    } \
    else

#define proc_enabled(a,b) \
    ((a & b) != 0) \
    { \
        verify_supported(IA32_VMX_PROCBASED_CTLS_MSR,b); \
    } \
    if ((a & b) != 0)

#define proc_disabled(a,b) \
    ((a & b) != 0) \
    { \
        verify_supported(IA32_VMX_PROCBASED_CTLS_MSR,b); \
    } \
    else

#define proc2_enabled(a,b) \
    ((a & b) != 0) \
    { \
        verify_supported(IA32_VMX_PROCBASED_CTLS2_MSR,b); \
    } \
    if ((a & b) != 0)

#define proc2_disabled(a,b) \
    ((a & b) != 0) \
    { \
        verify_supported(IA32_VMX_PROCBASED_CTLS2_MSR,b); \
    } \
    else

#define exit_enabled(a,b) \
    ((a & b) != 0) \
    { \
        verify_supported(IA32_VMX_EXIT_CTLS_MSR,b); \
    } \
    if ((a & b) != 0)

#define exit_disabled(a,b) \
    ((a & b) != 0) \
    { \
        verify_supported(IA32_VMX_EXIT_CTLS_MSR,b); \
    } \
    else

#define entry_enabled(a,b) \
    ((a & b) != 0) \
    { \
        verify_supported(IA32_VMX_ENTRY_CTLS_MSR,b); \
    } \
    if ((a & b) != 0)

#define entry_disabled(a,b) \
    ((a & b) != 0) \
    { \
        verify_supported(IA32_VMX_ENTRY_CTLS_MSR,b); \
    } \
    else

#endif
