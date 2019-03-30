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

#include <catch/catch.hpp>
#include <hippomocks.h>

#include <test/support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

uint64_t reg_data[38] = {0};
uint64_t *regs = &reg_data[0];

TEST_CASE("vector_to_str")
{
    CHECK(strcmp(vector_to_str(0x00U), "fault: divide by 0") == 0);
    CHECK(strcmp(vector_to_str(0x01U), "fault/trap: debug exception") == 0);
    CHECK(strcmp(vector_to_str(0x02U), "interrupt: nmi") == 0);
    CHECK(strcmp(vector_to_str(0x03U), "trap: breakpoint") == 0);
    CHECK(strcmp(vector_to_str(0x04U), "trap: overflow") == 0);
    CHECK(strcmp(vector_to_str(0x05U), "fault: bound range exceeded") == 0);
    CHECK(strcmp(vector_to_str(0x06U), "fault: invalid opcode") == 0);
    CHECK(strcmp(vector_to_str(0x07U), "fault: device not available (no math coprocessor") == 0);
    CHECK(strcmp(vector_to_str(0x08U), "abort: double fault") == 0);
    CHECK(strcmp(vector_to_str(0x09U), "fault: coprocessor segment overrun") == 0);
    CHECK(strcmp(vector_to_str(0x0AU), "fault: invalid TSS") == 0);
    CHECK(strcmp(vector_to_str(0x0BU), "fault: segment not present") == 0);
    CHECK(strcmp(vector_to_str(0x0CU), "fault: stack segment fault") == 0);
    CHECK(strcmp(vector_to_str(0x0DU), "fault: general protection fault") == 0);
    CHECK(strcmp(vector_to_str(0x0EU), "fault: page fault") == 0);
    CHECK(strcmp(vector_to_str(0x10U), "fault: x87 fpu floating point error") == 0);
    CHECK(strcmp(vector_to_str(0x11U), "fault: alignment check") == 0);
    CHECK(strcmp(vector_to_str(0x12U), "abort: machine check") == 0);
    CHECK(strcmp(vector_to_str(0x13U), "fault: simd floating point exception") == 0);
    CHECK(strcmp(vector_to_str(0x14U), "fault: virtualization exception") == 0);
    CHECK(strcmp(vector_to_str(0x16U), "undefined") == 0);
}

bool
ec_valid(unsigned int vector)
{
    switch (vector) {
        case 8:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 17:
            return true;

        default:
            return false;
    };
}

TEST_CASE("default_esr")
{
    MockRepository mocks;
    auto vcpu = setup_vcpu(mocks);

    for (auto i = 0U; i < 32U; ++i) {
        default_esr(i, 0, ec_valid(i), regs, vcpu);
    }
}

TEST_CASE("set_default_esrs")
{
    bfvmm::x64::idt idt{256};
    CHECK_NOTHROW(set_default_esrs(&idt, 8));
}

#endif
