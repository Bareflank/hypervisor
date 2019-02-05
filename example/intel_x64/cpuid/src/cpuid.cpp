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

#include <vmm.h>

using namespace bfvmm::intel_x64;

bool my_cpuid_handler(vcpu_t vcpu, cpuid::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    bfdebug_info(0, "This handler gets called when a guest runs CPUID 0xF00D");
    bfdebug_info(0, "The guest will observe the result 0xBEEF in register rax");
    vcpu->set_rax(0xBEEF);

    return true;
}

bool my_cpuid_handler_2(vcpu_t vcpu, cpuid::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    bfdebug_info(0, "An extra handler for special-purpose CPUID leaf 0x4BF00020");
    bfdebug_info(0, "This handler is only registered to vcpu 0");

    return false;
}

bool vmm_main(vcpu_t vcpu)
{
    auto handler = cpuid::handler(my_cpuid_handler);
    cpuid::emulate(vcpu, 0xF00D, handler);

    auto handler_2 = cpuid::handler(my_cpuid_handler_2);
    cpuid::emulate(vcpu, 0x4BF00020, handler_2);

    bfdebug_info(0, "CPUID example initialized");

    return true;
}
