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

// TIDY_EXCLUSION=-cert-err58-cpp
//
// Reason:
//     This test triggers on the use of a std::mutex being globally defined
//     from the EPT map.
//

#include <vmm.h>

using namespace bfvmm::intel_x64;

ept::mmap g_guest_map;

bool test_external_interrupt_handler(
    vcpu_t vcpu, external_interrupt_handler::info_t &info)
{
    bfignored(vcpu);

    vcpu->queue_external_interrupt(info.vector);

    return true;
}

bool vmm_init()
{
    ept::identity_map(g_guest_map, MAX_PHYS_ADDR);
    return true;
}

bool vmm_main(vcpu_t vcpu)
{
    vcpu->add_external_interrupt_handler(
        external_interrupt_handler::handler_delegate_t::create
        <test_external_interrupt_handler>()
    );

    vcpu->set_eptp(g_guest_map);

    return true;
}
