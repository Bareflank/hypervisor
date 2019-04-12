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

#ifndef IMPLEMENTATION_CPUID_INTEL_X64_H
#define IMPLEMENTATION_CPUID_INTEL_X64_H

#include "../interface/cpuid.h"
#include "../vmexit/cpuid.h"

// -----------------------------------------------------------------------------
// Defintion
// -----------------------------------------------------------------------------

///@cond

namespace bfvmm::intel_x64::implementation
{

class cpuid :
    public vmexit::cpuid
{
public:

    explicit cpuid(
        gsl::not_null<vcpu *> vcpu);
    VIRTUAL ~cpuid() = default;

    VIRTUAL void emulate(
        vcpu *vcpu, reg_t rax, reg_t rbx, reg_t rcx, reg_t rdx) noexcept;

    VIRTUAL cpuid_n::leaf_t leaf(const vcpu *vcpu) const;
    VIRTUAL cpuid_n::subleaf_t subleaf(const vcpu *vcpu) const;

public:

    cpuid(cpuid &&) = default;
    cpuid &operator=(cpuid &&) = default;

    cpuid(const cpuid &) = delete;
    cpuid &operator=(const cpuid &) = delete;

public:

#ifdef ENABLE_BUILD_TEST
    static void mock(
        MockRepository &mocks, gsl::not_null<vcpu *> vcpu);
#endif
};

}

///@endcond

#endif
