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

#ifndef VMEXIT_CPUID_INTEL_X64_H
#define VMEXIT_CPUID_INTEL_X64_H

#include <list>
#include <unordered_map>

#include "../interface/cpuid.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// @cond

namespace bfvmm::intel_x64::vmexit
{

class cpuid
{
public:

    explicit cpuid(
        gsl::not_null<vcpu *> vcpu);
    VIRTUAL ~cpuid() = default;

public:

    VIRTUAL void add_handler(
        cpuid_n::leaf_t leaf, const handler_delegate_t &d);
    VIRTUAL void add_emulator(
        cpuid_n::leaf_t leaf, const handler_delegate_t &d);
    VIRTUAL void execute(vcpu *vcpu) noexcept;

public:

    bool handle(vcpu *vcpu);

private:

    std::unordered_map<cpuid_n::leaf_t, std::list<handler_delegate_t>> m_handlers;
    std::unordered_map<cpuid_n::leaf_t, std::list<handler_delegate_t>> m_emulators;

public:

    cpuid(cpuid &&) = default;
    cpuid &operator=(cpuid &&) = default;

    cpuid(const cpuid &) = delete;
    cpuid &operator=(const cpuid &) = delete;

};

}

/// @endcond

#endif
