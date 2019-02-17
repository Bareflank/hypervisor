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

bool cpuid_emulate_handler(vcpu_t vcpu, cpuid::info_t &info)
{
    bfignored(info);

    bfdebug_info(0, "This handler gets called when a guest runs the cpuid");
    bfdebug_info(0, "instruction with a value 0xF00D in register eax.");
    bfdebug_info(0, "The guest will observe the result 0xBEEF in eax.");

    cpuid::emulate(vcpu, 0xBEEF, 0, 0, 0);

    return true;
}

bool cpuid_pass_through_handler(vcpu_t vcpu, cpuid::info_t &info)
{
    bfignored(info);

    bfdebug_info(0, "This handler passes-through the cpuid instruction that");
    bfdebug_info(0, "triggered a vmexit.");
    bfdebug_nhex(0, "CPUID leaf:", info.leaf);
    bfdebug_nhex(0, "CPUID subleaf:", info.subleaf);

    cpuid::pass_through(vcpu);

    return true;
}

bool vmm_main(vcpu_t vcpu)
{
    auto handler = cpuid::handler(cpuid_emulate_handler);
    cpuid::handle(vcpu, 0xF00D, handler);

    auto handler_2 = cpuid::handler(cpuid_pass_through_handler);
    cpuid::handle(vcpu, 0x8086, handler_2);

    bfdebug_info(0, "CPUID example initialized");

    return true;
}
