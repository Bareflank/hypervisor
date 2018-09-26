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
#include <bfconstants.h>
#include <bfthreadcontext.h>

#include <memory_manager/memory_manager.h>
#include <memory_manager/arch/x64/unique_map.h>

#include <hve/arch/intel_x64/vmcs.h>

#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

extern "C" void vmcs_launch(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

extern "C" void vmcs_promote(
    bfvmm::intel_x64::save_state_t *save_state, const void *gdt) noexcept;

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm
{
namespace intel_x64
{

vmcs::vmcs(vcpuid::type vcpuid) :
    m_save_state{std::make_unique<save_state_t>()},
    m_vmcs_region{static_cast<uint32_t *>(alloc_page()), free_page},
    m_vmcs_region_phys{g_mm->virtptr_to_physint(m_vmcs_region.get())}
{
    gsl::span<uint32_t> id{m_vmcs_region.get(), 1024};
    id[0] = gsl::narrow<uint32_t>(::intel_x64::msrs::ia32_vmx_basic::revision_id::get());

    m_save_state->vcpuid = vcpuid;

    bfdebug_transaction(1, [&](std::string * msg) {
        bfdebug_pass(1, "vmcs region", msg);
        bfdebug_subnhex(1, "virt address", m_vmcs_region.get(), msg);
        bfdebug_subnhex(1, "phys address", m_vmcs_region_phys, msg);
        bfdebug_pass(1, "save state", msg);
        bfdebug_subnhex(1, "virt address", m_save_state.get(), msg);
    });
}

void
vmcs::launch()
{
    this->load();

    auto ___ = gsl::on_failure([&] {
        ::intel_x64::vmcs::debug::dump(0);
        check::all();
    });

    if (vcpuid::is_hvm_vcpu(m_save_state->vcpuid)) {
        ::intel_x64::vm::launch_demote();
    }
    else {
        vmcs_launch(m_save_state.get());
        throw std::runtime_error("vmcs launch failed");
    }
}

void
vmcs::promote()
{
    auto gdt =
        bfvmm::x64::make_unique_map<uint64_t>(
            ::intel_x64::vmcs::guest_gdtr_base::get(),
            ::intel_x64::vmcs::guest_cr3::get(),
            ::intel_x64::vmcs::guest_gdtr_limit::size()
        );

    vmcs_promote(m_save_state.get(), gdt.get());
    throw std::runtime_error("vmcs promote failed");
}

void
vmcs::resume()
{
    vmcs_resume(m_save_state.get());
    throw std::runtime_error("vmcs resume failed");
}

void
vmcs::load()
{ ::intel_x64::vm::load(&m_vmcs_region_phys); }

}
}
