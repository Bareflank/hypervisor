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

#include <bfgsl.h>
#include <bfdebug.h>
#include <bfexception.h>

#include <hve/arch/intel_x64/vmx.h>
#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm
{
namespace intel_x64
{

vmx::vmx() :
    m_vmx_region{make_page<uint32_t>()},
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

    if (::intel_x64::msrs::ia32_vmx_basic::memory_type::get() != ::x64::memory_type::write_back) {
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
