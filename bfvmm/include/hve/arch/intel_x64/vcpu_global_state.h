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

#ifndef VCPU_GLOBAL_STATE_INTEL_X64_H
#define VCPU_GLOBAL_STATE_INTEL_X64_H

#include <intrinsics.h>

/// @cond
#pragma pack(push, 1)

namespace bfvmm::intel_x64
{

struct vcpu_global_state_t {

    uint64_t ia32_vmx_cr0_fixed0 {
        ::intel_x64::msrs::ia32_vmx_cr0_fixed0::get() |
        ::intel_x64::cr0::extension_type::mask
    };

    uint64_t ia32_vmx_cr4_fixed0 {
        ::intel_x64::msrs::ia32_vmx_cr4_fixed0::get()
    };
};

inline vcpu_global_state_t g_vcpu_global_state;

}

#pragma pack(pop)
/// @endcond

#endif
