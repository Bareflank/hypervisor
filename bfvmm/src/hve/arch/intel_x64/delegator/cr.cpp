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
#include <hve/arch/intel_x64/delegator/cr.h>

namespace bfvmm::intel_x64::cr
{

uintptr_t
emulate_rdgpr(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{
    using namespace ::intel_x64::vmcs;
    using namespace exit_qualification::control_register_access;

    switch (general_purpose_register::get()) {
        case general_purpose_register::rax:
            return vcpu->rax();

        case general_purpose_register::rbx:
            return vcpu->rbx();

        case general_purpose_register::rcx:
            return vcpu->rcx();

        case general_purpose_register::rdx:
            return vcpu->rdx();

        case general_purpose_register::rsp:
            return vcpu->rsp();

        case general_purpose_register::rbp:
            return vcpu->rbp();

        case general_purpose_register::rsi:
            return vcpu->rsi();

        case general_purpose_register::rdi:
            return vcpu->rdi();

        case general_purpose_register::r8:
            return vcpu->r08();

        case general_purpose_register::r9:
            return vcpu->r09();

        case general_purpose_register::r10:
            return vcpu->r10();

        case general_purpose_register::r11:
            return vcpu->r11();

        case general_purpose_register::r12:
            return vcpu->r12();

        case general_purpose_register::r13:
            return vcpu->r13();

        case general_purpose_register::r14:
            return vcpu->r14();

        default:
            return vcpu->r15();
    }
}

bool
delegator::handle(vcpu_t vcpu)
{
    using namespace ::intel_x64::vmcs;
    using namespace exit_qualification::control_register_access;

    switch (control_register_number::get()) {
        case 4: {
            auto val = emulate_rdgpr(vcpu);
            cr4_read_shadow::set(val);

            val |= ::intel_x64::cr4::vmx_enable_bit::mask;
            guest_cr4::set(val);

            return vcpu->advance();
        }

        default:
            break;
    }

    return false;
}

}
