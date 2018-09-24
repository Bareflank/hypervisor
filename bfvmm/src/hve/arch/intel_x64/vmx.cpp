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

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfexception.h>

#include <hve/arch/intel_x64/vmx.h>

#include <intrinsics.h>
#include <memory_manager/memory_manager.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm
{
namespace intel_x64
{

vmx::vmx() :
    m_vmx_region{static_cast<uint32_t *>(alloc_page()), free_page},
    m_vmx_region_phys{g_mm->virtptr_to_physint(m_vmx_region.get())}
{
    this->reset_vmx();
    this->setup_vmx_region();

    this->check_cpuid_vmx_supported();
    this->check_vmx_capabilities_msr();

    this->enable_vmx();

    this->check_ia32_vmx_cr0_fixed_msr();
    this->check_ia32_vmx_cr4_fixed_msr();
    this->check_ia32_feature_control_msr();
    this->check_v8086_disabled();

    this->execute_vmxon();

    bfdebug_pass(1, "vmx: complete");
}

vmx::~vmx()
{
    guard_exceptions([&]() {
        this->execute_vmxoff();
        this->disable_vmx();
    });

    bfdebug_pass(1, "~vmx: complete");
}

void
vmx::check_cpuid_vmx_supported()
{
    if (::intel_x64::cpuid::feature_information::ecx::vmx::is_disabled()) {
        throw std::runtime_error("VMX extensions not supported");
    }

    bfdebug_pass(1, "check vmx supported");
}

void
vmx::check_vmx_capabilities_msr()
{
    if (::intel_x64::msrs::ia32_vmx_basic::physical_address_width::is_enabled()) {
        throw std::runtime_error("invalid physical address width");
    }

    bfdebug_pass(1, "check vmx capabilities physical address width");

    if (::intel_x64::msrs::ia32_vmx_basic::memory_type::get() != x64::memory_type::write_back) {
        throw std::runtime_error("invalid memory type");
    }

    bfdebug_pass(1, "check vmx capabilities memory type");

    if (::intel_x64::msrs::ia32_vmx_basic::true_based_controls::is_disabled()) {
        throw std::runtime_error("invalid vmx true based controls");
    }

    bfdebug_pass(1, "check vmx capabilities true based controls supported");
}

void
vmx::check_ia32_vmx_cr0_fixed_msr()
{
    auto cr0 = ::intel_x64::cr0::get();
    auto ia32_vmx_cr0_fixed0 = ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get();
    auto ia32_vmx_cr0_fixed1 = ::intel_x64::msrs::ia32_vmx_cr0_fixed1::get();

    if (0 != ((~cr0 & ia32_vmx_cr0_fixed0) | (cr0 & ~ia32_vmx_cr0_fixed1))) {
        throw std::runtime_error("invalid cr0");
    }

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "check cr0 is valid", msg);
        bfdebug_subnhex(1, "cr0", cr0, msg);
        bfdebug_subnhex(1, "ia32_vmx_cr0_fixed0", ia32_vmx_cr0_fixed0, msg);
        bfdebug_subnhex(1, "ia32_vmx_cr0_fixed1", ia32_vmx_cr0_fixed1, msg);
    });
}

void
vmx::check_ia32_vmx_cr4_fixed_msr()
{
    auto cr4 = ::intel_x64::cr4::get();
    auto ia32_vmx_cr4_fixed0 = ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get();
    auto ia32_vmx_cr4_fixed1 = ::intel_x64::msrs::ia32_vmx_cr4_fixed1::get();

    if (0 != ((~cr4 & ia32_vmx_cr4_fixed0) | (cr4 & ~ia32_vmx_cr4_fixed1))) {
        throw std::runtime_error("invalid cr4");
    }

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "check cr4 is valid", msg);
        bfdebug_subnhex(1, "cr4", cr4, msg);
        bfdebug_subnhex(1, "ia32_vmx_cr4_fixed0", ia32_vmx_cr4_fixed0, msg);
        bfdebug_subnhex(1, "ia32_vmx_cr4_fixed1", ia32_vmx_cr4_fixed1, msg);
    });
}

void
vmx::check_ia32_feature_control_msr()
{
    if (::intel_x64::msrs::ia32_feature_control::lock_bit::is_enabled()) {
        bfdebug_pass(1, "check vmx feature controls lock bit");
        return;
    }

    ::intel_x64::msrs::ia32_feature_control::enable_vmx_outside_smx::enable();
    ::intel_x64::msrs::ia32_feature_control::lock_bit::enable();

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "vmx feature controls enable vmx outside smx enabled", msg);
        bfdebug_pass(1, "vmx feature controls lock bit enabled", msg);
    });
}

void
vmx::check_v8086_disabled()
{
    if (::x64::rflags::virtual_8086_mode::is_enabled()) {
        throw std::runtime_error("v8086 mode is not supported");
    }

    bfdebug_pass(1, "check v8086 disabled");
}

void
vmx::setup_vmx_region()
{
    gsl::span<uint32_t> id{m_vmx_region.get(), 1024};
    id[0] = gsl::narrow<uint32_t>(::intel_x64::msrs::ia32_vmx_basic::revision_id::get());

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "vmx region", msg);
        bfdebug_subnhex(1, "virt address", m_vmx_region.get(), msg);
        bfdebug_subnhex(1, "phys address", m_vmx_region_phys, msg);
    });
}

void
vmx::enable_vmx()
{
    ::intel_x64::cr4::vmx_enable_bit::enable();

    if (::intel_x64::cr4::vmx_enable_bit::is_disabled()) {
        throw std::runtime_error("failed to enable vmx");
    }

    bfdebug_pass(1, "vmx enabled");
}

void
vmx::disable_vmx()
{
    ::intel_x64::cr4::vmx_enable_bit::disable();
    bfdebug_test(1, "disable vmx", ::intel_x64::cr4::vmx_enable_bit::is_disabled());
}

void
vmx::reset_vmx()
{
    if (::intel_x64::cr4::vmx_enable_bit::is_enabled()) {
        bfalert_info(0, "VMX was not properly disabled. Attempting to reset VMX.");

        execute_vmxoff();
        disable_vmx();
    }
}

void
vmx::execute_vmxon()
{
    ::intel_x64::vmx::on(&m_vmx_region_phys);
    bfdebug_pass(1, "execute_vmxon: vmxon successfully executed");
}

void
vmx::execute_vmxoff()
{
    ::intel_x64::vmx::off();
    bfdebug_pass(1, "execute_vmxoff: vmxoff successfully executed");
}

}
}
