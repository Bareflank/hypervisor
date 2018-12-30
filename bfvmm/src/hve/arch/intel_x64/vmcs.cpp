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

#include <hve/arch/intel_x64/vmcs.h>
#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

extern "C" void vmcs_launch(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

extern "C" void vmcs_promote(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

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
    m_vcpuid{vcpuid},
    m_save_state{std::make_unique<save_state_t>()},
    m_vmcs_region{make_page<uint32_t>()},
    m_vmcs_region_phys{g_mm->virtptr_to_physint(m_vmcs_region.get())}
{
    this->clear();

    gsl::span<uint32_t> id{m_vmcs_region.get(), 1024};
    id[0] = gsl::narrow<uint32_t>(::intel_x64::msrs::ia32_vmx_basic::revision_id::get());

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
    try {
        if (vcpuid::is_host_vm_vcpu(m_vcpuid)) {
            ::intel_x64::vm::launch_demote();
        }
        else {
            vmcs_launch(m_save_state.get());
            throw std::runtime_error("vmcs launch failed");
        }
    }
    catch (...) {
        auto e = std::current_exception();

        this->check();
        std::rethrow_exception(e);
    }
}

void
vmcs::promote()
{
    vmcs_promote(m_save_state.get());
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
{
    ::intel_x64::vm::load(&m_vmcs_region_phys);
}

void
vmcs::clear()
{
    ::intel_x64::vm::clear(&m_vmcs_region_phys);
}

bool
vmcs::check() const noexcept
{
    try {
        check::all();
    }
    catch (std::exception &e) {
        bfdebug_transaction(0, [&](std::string * msg) {
            bferror_lnbr(0, msg);
            bferror_brk1(0, msg);
            bferror_info(0, typeid(e).name(), msg);
            bferror_brk1(0, msg);
            bferror_info(0, e.what(), msg);
        });

        return false;
    }

    return true;
}

}
}
