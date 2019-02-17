//
// Bareflank Hypervisor
// Copyright (C) 2018 Assured Information Security, Inc.
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

#include <vcpu/vcpu.h>
#include <entry/entry.h>

#include <hve/arch/intel_x64/delegator/cpuid.h>

#include "bfvmm.h"

namespace bfvmm::intel_x64::cpuid
{

// -----------------------------------------------------------------------------
// Built-in Handlers
// -----------------------------------------------------------------------------

bool
cpuid_ack_handler(vcpu_t vcpu, info_t &info)
{
    bfignored(info);
    vcpu->set_rax(0x4BF00001);
    return true;
}

bool
cpuid_main_handler(vcpu_t vcpu, info_t &info)
{
    bfignored(info);
    try {
        vcpu->init();

        vcpu->enable_vpid();
        vcpu->enable_wrcr0_exiting(0);
        vcpu->enable_wrcr4_exiting(0);

        bfdebug_info(0, "host os is" bfcolor_green " now " bfcolor_end "in a vm");
        return vmm_main(vcpu);
    }
    catch (...) {
        return false;
    }
}

bool
cpuid_fini_handler(vcpu_t vcpu, info_t &info)
{
    bfignored(info);

    try {
        vmm_fini(vcpu);
        bfdebug_info(0, "host os is" bfcolor_red " not " bfcolor_end "in a vm");
        vcpu->vmcs()->promote();
        return false;
    }
    catch (...) {
        return false;
    }
}

bool
cpuid_pass_through_handler(vcpu_t vcpu, info_t &info)
{
    bfignored(info);

    auto ret = ::x64::cpuid::get(
                   gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rax()),
                   gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rbx()),
                   gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rcx()),
                   gsl::narrow_cast<::x64::cpuid::field_type>(vcpu->rdx())
               );

    vcpu->set_rax(ret.rax);
    vcpu->set_rbx(ret.rbx);
    vcpu->set_rcx(ret.rcx);
    vcpu->set_rdx(ret.rdx);
    vcpu->advance();

    return true;
}

// -----------------------------------------------------------------------------
// CPUID Delegator Implementation
// -----------------------------------------------------------------------------

delegator::delegator()
{
    auto handler = handler(cpuid_pass_through_handler);
    m_default_handler = handler;

    handler = handler(cpuid_ack_handler);
    this->add_handler(0x4BF00000, handler);

    handler = handler(cpuid_main_handler);
    this->add_handler(0x4BF00010, handler);

    handler = handler(cpuid_fini_handler);
    this->add_handler(0x4BF00020, handler);
}

void
delegator::add_handler(cpuid::leaf_t leaf, const cpuid::delegate_t &d)
{
    m_handlers[leaf].push_front(d);
}

bool
delegator::handle(vcpu_t vcpu)
{
    auto leaf = vcpu->rax();
    auto subleaf = vcpu->rcx();

    const auto &hdlrs = m_handlers.find(leaf);
    struct info_t info = { leaf, subleaf, false };

    if (hdlrs != m_handlers.end()) {

        for (const auto &d : hdlrs->second) {
            if (d(vcpu, info)) {

                if (!info.ignore_advance) {
                    return vcpu->advance();
                }

                return true;
            }
        }
    }

    if (m_default_handler.is_valid()) {
        return m_default_handler(vcpu, info);
    }

    return false;
}

}
