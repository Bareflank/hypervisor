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

#include <commit_or_rollback.h>
#include <vmxon/vmxon_intel_x64.h>
#include <vmxon/vmxon_exceptions_intel_x64.h>
#include <memory_manager/memory_manager.h>

// =============================================================================
//  Implementation
// =============================================================================

vmxon_intel_x64::vmxon_intel_x64(intrinsics_intel_x64 *intrinsics) :
    m_intrinsics(intrinsics),
    m_vmxon_enabled(false)
{
}

void
vmxon_intel_x64::start()
{
    if (m_intrinsics == NULL)
        throw invalid_vmxon();

    if (this->is_vmx_operation_enabled() == true)
        throw vmxon_failure("vmxon already enabled");

    this->check_cpuid_vmx_supported();
    this->check_vmx_capabilities_msr();
    this->check_ia32_vmx_cr0_fixed_msr();
    this->check_ia32_feature_control_msr();
    this->check_v8086_disabled();

    auto cor1 = commit_or_rollback([&]
    { this->release_vmxon_region(); });

    this->create_vmxon_region();

    auto cor2 = commit_or_rollback([&]
    { this->disable_vmx_operation(); });

    this->enable_vmx_operation();

    if (this->is_vmx_operation_enabled() == false)
        throw vmxon_failure("failed to enable VMXON");

    this->check_ia32_vmx_cr4_fixed_msr();

    auto cor3 = commit_or_rollback([&]
    { this->execute_vmxoff(); });

    this->execute_vmxon();

    cor1.commit();
    cor2.commit();
    cor3.commit();
}

void
vmxon_intel_x64::stop()
{
    if (m_intrinsics == NULL)
        throw invalid_vmxon();

    this->execute_vmxoff();
    this->disable_vmx_operation();

    if (this->is_vmx_operation_enabled() == true)
        throw vmxon_failure("failed to disable VMXON");

    this->release_vmxon_region();
}

void
vmxon_intel_x64::check_cpuid_vmx_supported()
{
    if ((m_intrinsics->cpuid_ecx(1) & (1 << 5)) == 0)
        vmxon_failure("VMX extensions not supported");
}

void
vmxon_intel_x64::check_vmx_capabilities_msr()
{
    auto vmx_basic_msr = m_intrinsics->read_msr(IA32_VMX_BASIC_MSR);
    auto physical_address_width = (vmx_basic_msr >> 48) & 0x1;
    auto memory_type = (vmx_basic_msr >> 50) & 0xF;

    if (physical_address_width != 0)
        throw vmxon_capabilities_failure(
            vmx_basic_msr, physical_address_width);

    if (memory_type != 6)
        throw vmxon_capabilities_failure(
            vmx_basic_msr, memory_type);
}

void
vmxon_intel_x64::check_ia32_vmx_cr0_fixed_msr()
{
    auto cr0 = m_intrinsics->read_cr0();
    auto ia32_vmx_cr0_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED0_MSR);
    auto ia32_vmx_cr0_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR0_FIXED1_MSR);

    if (0 != ((~cr0 & ia32_vmx_cr0_fixed0) | (cr0 & ~ia32_vmx_cr0_fixed1)))
        throw vmxon_fixed_msr_failure(
            cr0, ia32_vmx_cr0_fixed0, ia32_vmx_cr0_fixed1);
}

void
vmxon_intel_x64::check_ia32_vmx_cr4_fixed_msr()
{
    auto cr4 = m_intrinsics->read_cr4();
    auto ia32_vmx_cr4_fixed0 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED0_MSR);
    auto ia32_vmx_cr4_fixed1 = m_intrinsics->read_msr(IA32_VMX_CR4_FIXED1_MSR);

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1)))
        throw vmxon_fixed_msr_failure(
            cr4, ia32_vmx_cr4_fixed0, ia32_vmx_cr4_fixed1);
}

void
vmxon_intel_x64::check_ia32_feature_control_msr()
{
    auto vmx_lock_bit = m_intrinsics->read_msr(IA32_FEATURE_CONTROL_MSR);

    if ((vmx_lock_bit & (1 << 0)) == 0)
        throw vmxon_failure("vmx lock bit == 0 is unsupported");
}

void
vmxon_intel_x64::check_v8086_disabled()
{
    if ((m_intrinsics->read_rflags() & RFLAGS_VM_VIRTUAL_8086_MODE) != 0)
        throw vmxon_failure("v8086 mode is not supported");
}

void
vmxon_intel_x64::enable_vmx_operation()
{
    auto cr4 = (m_intrinsics->read_cr4() | CR4_VMXE_VMX_ENABLE_BIT);
    m_intrinsics->write_cr4(cr4);
}

void
vmxon_intel_x64::disable_vmx_operation()
{
    auto cr4 = (m_intrinsics->read_cr4() & ~CR4_VMXE_VMX_ENABLE_BIT);
    m_intrinsics->write_cr4(cr4);
}

void
vmxon_intel_x64::create_vmxon_region()
{
    auto cor1 = commit_or_rollback([&]
    { this->release_vmxon_region(); });

    m_vmxon_region = std::make_unique<char[]>(4096);
    m_vmxon_region_phys = (uintptr_t)g_mm->virt_to_phys(m_vmxon_region.get());

    if ((m_vmxon_region_phys & 0x0000000000000FFF) != 0)
        throw invalid_alignmnet(
            "vmxon region not page aligned", m_vmxon_region_phys);

    auto region = (uint32_t *)m_vmxon_region.get();
    region[0] = m_intrinsics->read_msr(IA32_VMX_BASIC_MSR) & 0x7FFFFFFFF;

    cor1.commit();
}

void
vmxon_intel_x64::release_vmxon_region()
{
    m_vmxon_region.reset();
    m_vmxon_region_phys = 0;
}

void
vmxon_intel_x64::execute_vmxon()
{
    if (m_vmxon_enabled == true)
        throw vmxon_failure("vmxon has already been executed");

    if (m_intrinsics->vmxon(&m_vmxon_region_phys) == false)
        throw vmxon_failure("vmxon failed");

    m_vmxon_enabled = true;
}

void
vmxon_intel_x64::execute_vmxoff()
{
    if (m_vmxon_enabled == false)
        return;

    if (m_intrinsics->vmxoff() == false)
        throw vmxon_failure("vmxoff failed");

    m_vmxon_enabled = false;
}

bool
vmxon_intel_x64::is_vmx_operation_enabled()
{
    return m_intrinsics->read_cr4() & CR4_VMXE_VMX_ENABLE_BIT;
}
