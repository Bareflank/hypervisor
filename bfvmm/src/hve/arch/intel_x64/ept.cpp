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

namespace bfvmm::intel_x64
{

ept_handler::ept_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{ }

void ept_handler::set_eptp(ept::mmap *map)
{
    using namespace vmcs_n;
    using namespace vmcs_n::secondary_processor_based_vm_execution_controls;

    if (map != nullptr) {
        if (ept_pointer::phys_addr::get() == 0) {
            m_vcpu->global_state()->ia32_vmx_cr0_fixed0 &= ~::intel_x64::cr0::paging::mask;
            m_vcpu->global_state()->ia32_vmx_cr0_fixed0 &= ~::intel_x64::cr0::protection_enable::mask;

            ept_pointer::memory_type::set(ept_pointer::memory_type::write_back);
            ept_pointer::accessed_and_dirty_flags::disable();
            ept_pointer::page_walk_length_minus_one::set(3U);

            enable_ept::enable();
            unrestricted_guest::enable();
        }

        ept_pointer::phys_addr::set(map->eptp());
    }
    else {
        if (ept_pointer::phys_addr::get() != 0) {
            m_vcpu->global_state()->ia32_vmx_cr0_fixed0 |= ::intel_x64::cr0::paging::mask;
            m_vcpu->global_state()->ia32_vmx_cr0_fixed0 |= ::intel_x64::cr0::protection_enable::mask;

            ept_pointer::memory_type::set(0);
            ept_pointer::accessed_and_dirty_flags::disable();
            ept_pointer::page_walk_length_minus_one::set(0);

            enable_ept::disable();
            unrestricted_guest::disable();
        }

        ept_pointer::phys_addr::set(0);
    }
}

}
