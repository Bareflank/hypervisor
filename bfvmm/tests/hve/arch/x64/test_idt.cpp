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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <test/support.h>

TEST_CASE("idt_constructor_no_size")
{
    setup_test_support();
    bfvmm::x64::idt idt;
}

TEST_CASE("idt_constructor_zero_size")
{
    setup_test_support();
    CHECK_NOTHROW(bfvmm::x64::idt{0});
}

TEST_CASE("idt_constructor_size")
{
    setup_test_support();

    bfvmm::x64::idt idt{4};
    CHECK(idt.base() != 0);
    CHECK(idt.limit() == (4 * sizeof(bfvmm::x64::idt::interrupt_descriptor_type)) - 1);
}

TEST_CASE("idt_base")
{
    setup_test_support();

    bfvmm::x64::idt idt;
    CHECK(idt.base() == reinterpret_cast<bfvmm::x64::idt::integer_pointer>(g_idt.data()));
}

TEST_CASE("idt_limit")
{
    setup_test_support();

    bfvmm::x64::idt idt;
    CHECK(idt.limit() == (4 * sizeof(bfvmm::x64::idt::interrupt_descriptor_type)) - 1);
}
