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

#include "hve/arch/intel_x64/vcpu.h"
#include "sdk/cpuid.h"

namespace bfvmm::intel_x64::cpuid
{

void add_emulator(vcpu *vcpu, leaf_t leaf, handler_delegate_t handler)
{ vcpu->add_cpuid_emulator(leaf, handler); }

void add_handler(vcpu *vcpu, leaf_t leaf, handler_delegate_t handler)
{ vcpu->add_cpuid_handler(leaf, handler); }

void emulate(vcpu *vcpu, uint64_t rax, uint64_t rbx, uint64_t rcx, uint64_t rdx)
{
    vcpu->set_rax(set_bits(vcpu->rax(), 0x00000000FFFFFFFFULL, rax));
    vcpu->set_rbx(set_bits(vcpu->rbx(), 0x00000000FFFFFFFFULL, rbx));
    vcpu->set_rcx(set_bits(vcpu->rcx(), 0x00000000FFFFFFFFULL, rcx));
    vcpu->set_rdx(set_bits(vcpu->rdx(), 0x00000000FFFFFFFFULL, rdx));
}

void execute(vcpu *vcpu)
{ vcpu->execute_cpuid(); }

leaf_t get_leaf(vcpu *vcpu)
{ return vcpu->gr1(); }

leaf_t get_subleaf(vcpu *vcpu)
{ return vcpu->gr2(); }

}
