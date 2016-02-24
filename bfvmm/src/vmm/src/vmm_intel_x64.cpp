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

#include <iostream>
#include <vmm/vmm_intel_x64.h>

// =============================================================================
//  Helper Structs
// =============================================================================

struct vmxon_region
{
    uint32_t revision_id;
};

// =============================================================================
//  Implementation
// =============================================================================

vmm_intel_x64::vmm_intel_x64(intrinsics_intel_x64 *intrinsics) :
    m_vmxon_enabled(false),
    m_intrinsics(intrinsics)
{
}

vmm_error::type
vmm_intel_x64::start()
{
    vmm_error::type ret;

    if (m_intrinsics == 0)
        return vmm_error::failure;

    // The following process is documented in the Intel Software Developers
    // Manual, Section 31.5 Setup VMM & Teardown.

    ret = verify_cpuid_vmx_supported();
    if (ret != vmm_error::success)
        return ret;

    ret = verify_vmx_capabilities_msr();
    if (ret != vmm_error::success)
        return ret;

    ret = create_vmxon_region();
    if (ret != vmm_error::success)
        return ret;

    ret = verify_ia32_vmx_cr0_fixed_msr();
    if (ret != vmm_error::success)
        return ret;

    ret = enable_vmx_operation();
    if (ret != vmm_error::success)
        return ret;

    ret = verify_vmx_operation_enabled();
    if (ret != vmm_error::success)
        return ret;

    ret = verify_ia32_vmx_cr4_fixed_msr();
    if (ret != vmm_error::success)
        return ret;

    ret = verify_ia32_feature_control_msr();
    if (ret != vmm_error::success)
        return ret;

    // The following are additional checks that are documented in the VMXON
    // instructions itself in the Intel Software Developers Manual,
    // Section 30.3

    ret = verify_v8086_disabled();
    if (ret != vmm_error::success)
        return ret;

    // Finally, execute the VMX on instruction to enter VMX operation.
    // This places the host OS (code that is currently running) in VMX-root.
    // The next step will be to launch the VMCS for the host OS, leaving only
    // the VMM in VMX-root, and placing the host OS into VMX-nonroot.

    ret = execute_vmxon();
    if (ret != vmm_error::success)
        return ret;

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::stop()
{
    vmm_error::type ret;

    if (m_intrinsics == 0)
        return vmm_error::failure;

    // We don't have to do any checks to get ourselves out of the VMX
    // root operation. We simply need to reverse what we did to get into
    // VMX operation

    ret = execute_vmxoff();

    if (ret != vmm_error::success)
        return ret;

    ret = disable_vmx_operation();
    if (ret != vmm_error::success)
        return ret;

    ret = verify_vmx_operation_disabled();
    if (ret != vmm_error::success)
        return ret;

    ret = release_vmxon_region();
    if (ret != vmm_error::success)
        return ret;

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::verify_cpuid_vmx_supported()
{
    auto cpuid_eax = m_intrinsics->cpuid_ecx(1);

    // The CPUID instruction is huge, so we don't use macros here. For further
    // information on how this works, see the Intel Software Developers Manual,
    // CPUID instruction reference, table 3-19

    if ((cpuid_eax & (1 << 5)) == 0)
    {
        std::cout << "verify_cpuid_vmx_supported failed: "
                  << "VMX extensions not supported" << std::endl;
        return vmm_error::not_supported;
    }

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::verify_vmx_capabilities_msr()
{
    auto vmx_basic_msr = m_intrinsics->read_msr(IA32_VMX_BASIC_MSR);

    // The information regading this MSR can be found in appendix A.1. For
    // the VMX capabilities check, we need the following:
    //
    // - Bit 48 indicates the width of the physical addresses that may be
    //   used for the VMXON region, each VMCS, and data structures referenced
    //   by pointers in a VMCS (I/O bitmaps, virtual-APIC page, MSR areas for
    //   VMX transi- tions). If the bit is 0, these addresses are limited to
    //   the processor’s physical-address width. If the bit is 1, these
    //   addresses are limited to 32 bits. This bit is always 0 for processors
    //   that support Intel 64 architecture.
    //
    // - Bits 53:50 report the memory type that should be used for the VMCS,
    //   for data structures referenced by pointers in the VMCS (I/O bitmaps,
    //   virtual-APIC page, MSR areas for VMX transitions), and for the MSEG
    //   header. If software needs to access these data structures (e.g., to
    //   modify the contents of the MSR bitmaps), it can configure the paging
    //   structures to map them into the linear-address space. If it does so,
    //   it should establish mappings that use the memory type reported bits
    //   53:50 in this MSR.3
    //
    //   0 = uncacheable
    //   6 = writeback

    auto physical_address_width = (vmx_basic_msr >> 48) & 0x1;
    auto memory_type = (vmx_basic_msr >> 50) & 0xF;

    if (physical_address_width != 0)
    {
        std::cout << "verify_vmx_capabilities_msr failed: "
                  << "vmx capabilities MSR is reporting an unsupported physical address width: "
                  << physical_address_width << std::endl;
        return vmm_error::not_supported;
    }

    if (memory_type != 6)
    {
        std::cout << "verify_vmx_capabilities_msr failed: "
                  << "vmx capabilities MSR is reporting an unsupported memory type: "
                  << memory_type << std::endl;
        return vmm_error::not_supported;
    }

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::verify_ia32_vmx_cr0_fixed_msr()
{
    auto cr0 = m_intrinsics->read_cr0();
    auto ia32_vmx_cr0_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED0_MSR);
    auto ia32_vmx_cr0_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED1_MSR);

    // The information regading this MSR can be found in appendix A.7.
    //
    // The IA32_VMX_CR0_FIXED0 MSR (index 486H) and IA32_VMX_CR0_FIXED1 MSR
    // (index 487H) indicate how bits in CR0 may be set in VMX operation.
    // They report on bits in CR0 that are allowed to be 0 and to be 1,
    // respectively, in VMX operation. If bit X is 1 in IA32_VMX_CR0_FIXED0,
    // then that bit of CR0 is fixed to 1 in VMX operation. Similarly, if
    // bit X is 0 in IA32_VMX_CR0_FIXED1, then that bit of CR0 is fixed to 0
    // in VMX operation.

    if (0 != ((~cr0 & ia32_vmx_cr0_fixed0) | (cr0 & ~ia32_vmx_cr0_fixed1)))
    {
        std::cout << "verify_ia32_vmx_cr0_fixed_msr failed. "
                  << "cr0 incorrectly setup: " << std::endl
                  << std::hex
                  << "    - cr0: 0x" << cr0 << " " << std::endl
                  << "    - ia32_vmx_cr0_fixed0: 0x" << ia32_vmx_cr0_fixed0 << std::endl
                  << "    - ia32_vmx_cr0_fixed1: 0x" << ia32_vmx_cr0_fixed1 << std::endl
                  << std::dec;
        return vmm_error::not_supported;
    }

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::verify_ia32_vmx_cr4_fixed_msr()
{
    auto cr4 = m_intrinsics->read_cr4();
    auto ia32_vmx_cr4_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED0_MSR);
    auto ia32_vmx_cr4_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED1_MSR);

    // The information regading this MSR can be found in appendix A.7.
    //
    // The IA32_VMX_CR4_FIXED0 MSR (index 488H) and IA32_VMX_CR4_FIXED1 MSR
    // (index 489H) indicate how bits in CR4 may be set in VMX operation.
    // They report on bits in CR4 that are allowed to be 0 and 1,
    // respectively, in VMX operation. If bit X is 1 in IA32_VMX_CR4_FIXED0,
    // then that bit of CR4 is fixed to 1 in VMX operation. Similarly, if
    // bit X is 0 in IA32_VMX_CR4_FIXED1, then that bit of CR4 is fixed to 0
    // in VMX operation.

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1)))
    {
        std::cout << "verify_ia32_vmx_cr4_fixed_msr failed. "
                  << "cr4 incorrectly setup: " << std::endl
                  << std::hex
                  << "    - cr4: 0x" << cr4 << " " << std::endl
                  << "    - ia32_vmx_cr4_fixed0: 0x" << ia32_vmx_cr4_fixed0 << std::endl
                  << "    - ia32_vmx_cr4_fixed1: 0x" << ia32_vmx_cr4_fixed1 << std::endl
                  << std::dec;
        return vmm_error::not_supported;
    }

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::verify_ia32_feature_control_msr()
{
    auto ia32_feature_control = m_intrinsics->read_msr(IA32_FEATURE_CONTROL_MSR);

    if ((ia32_feature_control & (1 << 0)) == 0)
    {
        std::cout << "verify_ia32_feature_control_msr failed: "
                  << "feature control MSR is reporting the lock bit is not set: "
                  << std::hex << "0x" << ia32_feature_control << std::dec
                  << std::endl;
        return vmm_error::not_supported;
    }

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::verify_v8086_disabled()
{
    auto rflags = m_intrinsics->read_rflags();

    if ((rflags & RFLAGS_VM_VIRTUAL_8086_MODE) != 0)
    {
        std::cout << "verify_v8086_disabled failed: "
                  << "v8086 is currently enabled" << std::endl;
        return vmm_error::not_supported;
    }

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::verify_vmx_operation_enabled()
{
    auto cr4 = m_intrinsics->read_cr4();

    if ((cr4 & CR4_VMXE_VMX_ENABLE_BIT) == 0)
    {
        std::cout << "verify_vmx_operation_enabled failed: "
                  << "CR4_VMXE_VMX_ENABLE_BIT is cleared" << std::endl;
        return vmm_error::failure;
    }

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::verify_vmx_operation_disabled()
{
    auto cr4 = m_intrinsics->read_cr4();

    if ((cr4 & CR4_VMXE_VMX_ENABLE_BIT) != 0)
    {
        std::cout << "verify_vmx_operation_disabled failed: "
                  << "CR4_VMXE_VMX_ENABLE_BIT is set" << std::endl;
        return vmm_error::failure;
    }

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::enable_vmx_operation()
{
    auto cr4 = m_intrinsics->read_cr4();
    auto vmxe_vmx_enable_bit_set = cr4 | CR4_VMXE_VMX_ENABLE_BIT;

    m_intrinsics->write_cr4(vmxe_vmx_enable_bit_set);

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::disable_vmx_operation()
{
    auto cr4 = m_intrinsics->read_cr4();
    auto vmxe_vmx_enable_bit_cleared = cr4 & ~CR4_VMXE_VMX_ENABLE_BIT;

    m_intrinsics->write_cr4(vmxe_vmx_enable_bit_cleared);

    return vmm_error::success;
    return verify_vmx_operation_disabled();
}

vmm_error::type
vmm_intel_x64::create_vmxon_region()
{
    m_vmxon_page = new char[4096];
    if (!m_vmxon_page)
    {
        std::cout << "create_vmxon_region failed: "
                  << "out of memory" << std::endl;
        return vmm_error::out_of_memory;
    }

    if (((uintptr_t)g_mm->virt_to_phys(m_vmxon_page) & 0x0000000000000FFF) != 0)
    {
        std::cout << "create_vmxon_region failed: "
                  << "the allocated page is not page aligned:" << std::endl
                  << "    - page phys: " << g_mm->virt_to_phys(m_vmxon_page)
                  << std::endl;
        return vmm_error::not_supported;
    }

    // auto buf = (char *)m_vmxon_page.virt_addr();
    auto reg = (vmxon_region *)m_vmxon_page;

    // // The information regading this MSR can be found in appendix A.1. For
    // // the VMX capabilities check, we need the following:
    // //
    // // - Bits 30:0 contain the 31-bit VMCS revision identifier used by the
    // //   processor. Processors that use the same VMCS revision identifier use
    // //   the same size for VMCS regions (see subsequent item on bits 44:32)

    for (auto i = 0U; i < vmxon_region_size(); i++)
        m_vmxon_page[i] = 0;

    reg->revision_id = m_intrinsics->read_msr(IA32_VMX_BASIC_MSR) & 0x7FFFFFFFF;

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::release_vmxon_region()
{
    delete m_vmxon_page;

    return vmm_error::success;
}

vmm_error::type
vmm_intel_x64::execute_vmxon()
{
    auto phys = g_mm->virt_to_phys(m_vmxon_page);

    // For some reason, the VMXON instruction takes the address of a memory
    // location that has the address of the VMXON region, which sadly is not
    // well documented in the Intel manual.

    if (m_vmxon_enabled == true)
        return vmm_error::success;

    if (m_intrinsics->vmxon(&phys) == false)
    {
        std::cout << "execute_vmxon failed" << std::endl;
        return vmm_error::failure;
    }

    m_vmxon_enabled = true;
    std::cout << "vmxon: success" << std::endl;

    return vmm_error::success;
}


vmm_error::type
vmm_intel_x64::execute_vmxoff()
{
    // The VMXOFF instruction requires that the CPU be in VMX root operation.
    // If it is not, you can get an underfined intrustion error (or invalid
    // opcode). If we are not in VMX root operation it means that VMXON was not
    // run, was not successful, or was run on a different CPU that the one we
    // are running VMXOFF on.

    if (m_vmxon_enabled == false)
        return vmm_error::success;

    if (m_intrinsics->vmxoff() == false)
    {
        std::cout << "execute_vmxoff failed" << std::endl;
        return vmm_error::failure;
    }

    m_vmxon_enabled = false;

    std::cout << "vmxoff: success" << std::endl;

    return vmm_error::success;
}

uint64_t
vmm_intel_x64::vmxon_region_size()
{
    auto vmx_basic_msr = m_intrinsics->read_msr(IA32_VMX_BASIC_MSR);

    // The information regading this MSR can be found in appendix A.1. For
    // the VMX capabilities check, we need the following:
    //
    // - Bits 44:32 report the number of bytes that software should allocate
    //   for the VMXON region and any VMCS region. It is a value greater
    //   than 0 and at most 4096 (bit 44 is set if and only if bits 43:32 are
    //   clear).
    //
    //   Note: We basically ignore the above bits and just allocate 4K for each
    //   VMX region. The only thing we do with this function is ensure that
    //   the page that we were given is at least this big

    return (vmx_basic_msr >> 32) & 0x1FFF;
}
