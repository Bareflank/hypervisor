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

#include <hippomocks.h>
#include <catch/catch.hpp>
#include <hve/arch/x64/idt.h>
#include <hve/arch/intel_x64/nmi.h>
#include <arch/intel_x64/vmcs/32bit_control_fields.h>
#include <test/support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("set_nmi_handler")
{
    bfvmm::x64::idt idt{256};
    CHECK_NOTHROW(set_nmi_handler(&idt, 8));
}

TEST_CASE("inject_nmi")
{
    namespace int_info = ::intel_x64::vmcs::vm_entry_interruption_information;

    int_info::set(0);
    CHECK_NOTHROW(inject_nmi());

    CHECK(int_info::vector::get() == 2);
    CHECK(int_info::interruption_type::get() == int_info::interruption_type::non_maskable_interrupt);
    CHECK(int_info::valid_bit::is_enabled());
}

#endif
