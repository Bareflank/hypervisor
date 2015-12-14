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

#include <iomanip>
#include <iostream>

#include <vmcs/vmcs_intel_x64.h>

bool
vmcs_intel_x64::check_guest_checks_on_guest_control_registers_debug_registers_and_msrs()
{
    auto result = true;

    result &= check_guest_cr0_for_unsupported_bits();
    result &= check_guest_cr0_verify_paging_enabled();
    result &= check_guest_cr0_verify_protected_mode_enabled();
    result &= check_guest_cr4_for_unsupported_bits();
    result &= check_guest_load_debug_controls_verify_reserved_bits_equal_zero();
    result &= check_guest_verify_ia_32e_mode_enabled();
    result &= check_guest_cr4_verify_pae_enabled();
    result &= check_guest_cr3_for_unsupported_bits();
    result &= check_guest_load_debug_controls_verify_verify_dr7();
    result &= check_guest_ia32_sysenter_esp_canonical_address();
    result &= check_guest_ia32_sysenter_eip_canonical_address();
    result &= check_guest_ia32_perf_global_ctrl_for_reserved_bits();
    result &= check_guest_ia32_pat_for_unsupported_bits();
    result &= check_guest_verify_load_ia32_efer_enabled();
    result &= check_guest_ia32_efer_for_reserved_bits();
    result &= check_guest_ia32_efer_set();

    return result;
}

bool
vmcs_intel_x64::check_guest_cr0_for_unsupported_bits()
{
    auto cr0 = vmread(VMCS_GUEST_CR0);
    auto ia32_vmx_cr0_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED0_MSR);
    auto ia32_vmx_cr0_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED1_MSR);

    if (0 != ((~cr0 & ia32_vmx_cr0_fixed0) | (cr0 & ~ia32_vmx_cr0_fixed1)))
    {
        std::cout << "check_guest_cr0_for_unsupported_bits failed. "
                  << "guest cr0 incorrectly setup: " << std::endl
                  << std::hex
                  << "    - cr0: 0x" << cr0 << " " << std::endl
                  << "    - ia32_vmx_cr0_fixed0: 0x" << ia32_vmx_cr0_fixed0 << std::endl
                  << "    - ia32_vmx_cr0_fixed1: 0x" << ia32_vmx_cr0_fixed1 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cr0_verify_paging_enabled()
{
    auto cr0 = vmread(VMCS_GUEST_CR0);

    if((cr0 & CR0_PG_PAGING) == 0)
    {
        std::cout << "check_guest_cr0_verify_paging_enabled failed. "
                  << "guest cr0 does not have paging enabled: " << std::endl
                  << std::hex
                  << "    - cr0: 0x" << cr0 << " " << std::endl
                  << std::dec;
        return false;
    }
}

bool
vmcs_intel_x64::check_guest_cr0_verify_protected_mode_enabled()
{
    auto cr0 = vmread(VMCS_GUEST_CR0);

    if((cr0 & CRO_PE_PROTECTION_ENABLE) == 0)
    {
        std::cout << "check_guest_cr0_verify_protected_mode_enabled failed. "
                  << "guest cr0 does not have protected mode enabled: " << std::endl
                  << std::hex
                  << "    - cr0: 0x" << cr0 << " " << std::endl
                  << std::dec;
        return false;
    }
}

bool
vmcs_intel_x64::check_guest_cr4_for_unsupported_bits()
{
    auto cr4 = vmread(VMCS_GUEST_CR4);
    auto ia32_vmx_cr4_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED0_MSR);
    auto ia32_vmx_cr4_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED1_MSR);

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1)))
    {
        std::cout << "check_guest_cr4_for_unsupported_bits failed. "
                  << "guest cr4 incorrectly setup: " << std::endl
                  << std::hex
                  << "    - cr4: 0x" << cr4 << " " << std::endl
                  << "    - ia32_vmx_cr4_fixed0: 0x" << ia32_vmx_cr4_fixed0 << std::endl
                  << "    - ia32_vmx_cr4_fixed1: 0x" << ia32_vmx_cr4_fixed1 << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_load_debug_controls_verify_reserved_bits_equal_zero()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    if ((controls & VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_load_debug_controls_verify_reserved_bits_equal_zero"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_verify_ia_32e_mode_enabled()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    if ((controls & VM_ENTRY_CONTROL_IA_32E_MODE_GUEST) == 0)
    {
        std::cout << "check_guest_verify_ia_32e_mode_enabled failed: "
                  << "only 64bit guests are supported. ia_32e mode not enabled"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_cr4_verify_pae_enabled()
{
    auto cr4 = vmread(VMCS_GUEST_CR4);

    if((cr4 & CR4_PAE_PHYSICAL_ADDRESS_EXTENSIONS) == 0)
    {
        std::cout << "check_guest_cr4_verify_pae_enabled failed. "
                  << "guest cr4 does not have pae enabled: " << std::endl
                  << std::hex
                  << "    - cr4: 0x" << cr4 << " " << std::endl
                  << std::dec;
        return false;
    }
}

bool
vmcs_intel_x64::check_guest_cr3_for_unsupported_bits()
{
    auto cr3 = vmread(VMCS_GUEST_CR3);

    // The manual states that CPUID will return the total number of bits that
    // are supported, which at the moment is 42, and is unlikely to change for
    // a while (256 terabytes). If this code triggers a failure do to being
    // hardcoded, cpuid(0x80000008) -> eax[7:0] will return the number of
    // bits that are supported on the system.

    if ((cr3 & ~0x3FFFFFFFFFF) != 0)
    {
        std::cout << "check_guest_cr3_for_unsupported_bits failed. "
                  << "guest cr3 has an unsupported address width: " << std::endl
                  << std::hex
                  << "    - cr3: 0x" << cr3 << " " << std::endl
                  << std::dec;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_load_debug_controls_verify_verify_dr7()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    if ((controls & VM_ENTRY_CONTROL_LOAD_DEBUG_CONTROLS) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_load_debug_controls_verify_verify_dr7"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_sysenter_esp_canonical_address()
{
    auto esp = vmread(VMCS_GUEST_IA32_SYSENTER_EIP);

    if (check_is_address_canonical(esp) == false)
    {
        std::cout << "check_guest_ia32_sysenter_esp_canonical_address failed. "
                  << "guest ia32_sysenter_esp has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - ia32_sysenter_esp: 0x" << esp << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_sysenter_eip_canonical_address()
{
    auto eip = vmread(VMCS_GUEST_IA32_SYSENTER_EIP);

    if (check_is_address_canonical(eip) == false)
    {
        std::cout << "check_guest_ia32_sysenter_eip_canonical_address failed. "
                  << "guest ia32_sysenter_eip has a non-canonical address: " << std::endl
                  << std::hex
                  << "    - ia32_sysenter_eip: 0x" << eip << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_perf_global_ctrl_for_reserved_bits()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    if ((controls & VM_EXIT_CONTROL_LOAD_IA32_PERF_GLOBAL_CTRL) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_ia32_perf_global_ctrl_for_reserved_bits"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_pat_for_unsupported_bits()
{
    auto controls = vmread(VMCS_VM_EXIT_CONTROLS);

    if ((controls & VM_EXIT_CONTROL_LOAD_IA32_PAT) != 0)
    {
        std::cout << "unimplemented VMCS check: "
                  << "check_guest_ia32_pat_for_unsupported_bits"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_verify_load_ia32_efer_enabled()
{
    auto controls = vmread(VMCS_VM_ENTRY_CONTROLS);

    if ((controls & VM_ENTRY_CONTROL_LOAD_IA32_EFER) == 0)
    {
        std::cout << "check_guest_verify_load_ia32_efer_enabled: "
                  << "only 64bit guests are supported. load_ia32_efer must be enabled"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_efer_for_reserved_bits()
{
    auto vmcs_guest_ia32_efer_full = vmread(VMCS_GUEST_IA32_EFER_FULL);

    if ((vmcs_guest_ia32_efer_full & 0xFFFFFFFFFFFFF2FE) != 0)
    {
        std::cout << "check_guest_ia32_efer_for_reserved_bits failed: "
                  << "the reserved bits in is32_efer must be zero"
                  << std::endl;
        return false;
    }

    return true;
}

bool
vmcs_intel_x64::check_guest_ia32_efer_set()
{
    auto vmcs_guest_ia32_efer_full = vmread(VMCS_GUEST_IA32_EFER_FULL);

    if ((vmcs_guest_ia32_efer_full & 0x0000000000000500) != 0x0000000000000500)
    {
        std::cout << "check_guest_ia32_efer_set failed. "
                  << "guest ia32_efer msr does not have LME and LMA set: " << std::endl
                  << std::hex
                  << "    - ia32_efer: 0x" << vmcs_guest_ia32_efer_full << " " << std::endl
                  << std::dec;

        return false;
    }

    return true;
}
