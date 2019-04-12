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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/implementation/cpuid.h>

using namespace vmcs_n::exit_reason;

namespace bfvmm::intel_x64::implementation
{

cpuid::cpuid(gsl::not_null<vcpu *> vcpu) :
    vmexit::cpuid{vcpu}
{ }

void
cpuid::emulate(
    vcpu *vcpu, reg_t rax, reg_t rbx, reg_t rcx, reg_t rdx) noexcept
{
    vcpu->set_rax(set_bits(vcpu->rax(), 0x00000000FFFFFFFFULL, rax));
    vcpu->set_rbx(set_bits(vcpu->rbx(), 0x00000000FFFFFFFFULL, rbx));
    vcpu->set_rcx(set_bits(vcpu->rcx(), 0x00000000FFFFFFFFULL, rcx));
    vcpu->set_rdx(set_bits(vcpu->rdx(), 0x00000000FFFFFFFFULL, rdx));
}

cpuid_n::leaf_t
cpuid::leaf(const vcpu *vcpu) const
{
    // if (vcpu->exit_reason() != basic_exit_reason::cpuid) {
    //     throw std::runtime_error(
    //         "accessed cpuid_leaf() from non-cpuid vmexit");
    // }

    return vcpu->gr1();
}

cpuid_n::subleaf_t
cpuid::subleaf(const vcpu *vcpu) const
{
    // if (vcpu->exit_reason() != basic_exit_reason::cpuid) {
    //     throw std::runtime_error(
    //         "accessed cpuid_leaf() from non-cpuid vmexit");
    // }

    return vcpu->gr2();
}

#ifdef ENABLE_BUILD_TEST

void
cpuid::mock(
    MockRepository &mocks, gsl::not_null<vcpu *> vcpu)
{
    mocks.OnCall(vcpu->cpuid_impl().get(), cpuid::add_handler);
    mocks.OnCall(vcpu->cpuid_impl().get(), cpuid::add_emulator);
    mocks.OnCall(vcpu->cpuid_impl().get(), cpuid::execute);
    mocks.OnCall(vcpu->cpuid_impl().get(), cpuid::emulate);
    mocks.OnCall(vcpu->cpuid_impl().get(), cpuid::leaf);
    mocks.OnCall(vcpu->cpuid_impl().get(), cpuid::subleaf);
}

#endif

}
