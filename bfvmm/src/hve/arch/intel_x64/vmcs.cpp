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
#include <bfconstants.h>
#include <bfthreadcontext.h>

#include <hve/arch/intel_x64/vmcs.h>
#include <hve/arch/intel_x64/check.h>
#include <hve/arch/intel_x64/vcpu.h>

#include <intrinsics.h>

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------

extern "C" void vmcs_launch(
    bfvmm::intel_x64::vcpu_state_t *vcpu_state) noexcept;

extern "C" void vmcs_promote(
    bfvmm::intel_x64::vcpu_state_t *vcpu_state) noexcept;

extern "C" void vmcs_resume(
    bfvmm::intel_x64::vcpu_state_t *vcpu_state) noexcept;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace bfvmm::intel_x64
{

vmcs::vmcs(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
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
    });
}

void
vmcs::launch()
{
    try {
        if (m_vcpu->is_host_vm_vcpu()) {
            ::intel_x64::vm::launch_demote();
        }
        else {
            vmcs_launch(m_vcpu->state().get());
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
    vmcs_promote(m_vcpu->state());
    throw std::runtime_error("vmcs promote failed");
}

void
vmcs::resume()
{
    vmcs_resume(m_vcpu->state());

    this->check();
    throw std::runtime_error("vmcs resume failed");
}

void
vmcs::load()
{ ::intel_x64::vm::load(&m_vmcs_region_phys); }

void
vmcs::clear()
{ ::intel_x64::vm::clear(&m_vmcs_region_phys); }

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
