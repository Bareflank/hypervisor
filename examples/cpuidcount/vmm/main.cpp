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
#include <atomic>

std::atomic<uint64_t> g_count{0};

void
global_init()
{
    bfdebug_info(0, "running cpuidcount example");
    bfdebug_lnbr(0);

    g_count = 0;
}

void
global_fini()
{ bfdebug_ndec(0, "global count", g_count); }

bool
handle_cpuid(vcpu_t *vcpu)
{
    bfignored(vcpu);

    g_count++;
    vcpu->data<uint64_t &>()++;

    return false;
}

void
vcpu_init_nonroot(vcpu_t *vcpu)
{
    using namespace vmcs_n::exit_reason::basic_exit_reason;

    vcpu->add_exit_handler_for_reason(
        cpuid, handle_cpuid);

    vcpu->set_data<uint64_t>(0);
}

void
vcpu_fini_nonroot(vcpu_t *vcpu)
{ bfdebug_ndec(0, "vcpu count", vcpu->data<uint64_t>()); }

// Expected Output (make dump)
//
// [0x0] DEBUG: running cpuidcount example
// [0x0] DEBUG:
// [0x0] DEBUG: host os is now in a vm
// ...
// [0x0] DEBUG: host os is not in a vm
// [0x0] DEBUG: vcpu count                                                      xxx
// [0x0] DEBUG: global count                                                    xxx
