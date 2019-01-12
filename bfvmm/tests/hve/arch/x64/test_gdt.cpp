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

TEST_CASE("gdt_constructor_no_size")
{
    setup_test_support();
    bfvmm::x64::gdt gdt;
}

TEST_CASE("gdt_constructor_zero_size")
{
    CHECK_NOTHROW(bfvmm::x64::gdt{0});
}

TEST_CASE("gdt_constructor_size")
{
    bfvmm::x64::gdt gdt{4};
    CHECK(gdt.base() != 0);
    CHECK(gdt.limit() == 4 * sizeof(bfvmm::x64::gdt::segment_descriptor_type) - 1);
}

TEST_CASE("gdt_base")
{
    g_gdtr.base = reinterpret_cast<bfvmm::x64::gdt::integer_pointer>(g_gdt.data());

    bfvmm::x64::gdt gdt;
    CHECK(gdt.base() == reinterpret_cast<bfvmm::x64::gdt::integer_pointer>(g_gdt.data()));
}

TEST_CASE("gdt_limit")
{
    g_gdtr.limit = 42;

    bfvmm::x64::gdt gdt;
    CHECK(gdt.limit() == 42);
}

TEST_CASE("gdt_set_base_zero_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.set_base(0, 0x10));
}

TEST_CASE("gdt_set_base_invalid_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.set_base(1000, 0x10));
}

TEST_CASE("gdt_set_base_tss_at_end_of_gdt")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.set_base(7, 0x10));
}

TEST_CASE("gdt_set_base_descriptor_success")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_NOTHROW(gdt.set_base(5, 0xBBBBBBBB12345678));
    CHECK(gdt.m_gdt.at(5) == 0x12FFFF345678FFFF);
}

TEST_CASE("gdt_set_base_tss_success")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_NOTHROW(gdt.set_base(6, 0x1234567812345678));
    CHECK(gdt.m_gdt.at(6) == 0x12FF8F345678FFFF);
    CHECK(gdt.m_gdt.at(7) == 0x0000000012345678);
}

TEST_CASE("gdt_base_zero_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.base(0));
}

TEST_CASE("gdt_base_invalid_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.base(1000));
}

TEST_CASE("gdt_base_tss_at_end_of_gdt")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.base(7));
}

TEST_CASE("gdt_base_descriptor_success")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    gdt.m_gdt.at(5) = 0x12FFFF345678FFFF;
    CHECK(gdt.base(5) == 0x0000000012345678);
}

TEST_CASE("gdt_base_tss_success")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    gdt.m_gdt.at(6) = 0x12FF8F345678FFFF;
    gdt.m_gdt.at(7) = 0x0000000012345678;
    CHECK(gdt.base(6) == 0x1234567812345678);
}

TEST_CASE("gdt_set_limit_zero_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.set_limit(0, 0x10));
}

TEST_CASE("gdt_set_limit_invalid_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.set_limit(1000, 0x10));
}

TEST_CASE("gdt_set_limit_descriptor_success")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_NOTHROW(gdt.set_limit(5, 0x12345678));
    CHECK(gdt.m_gdt.at(5) == 0xFFF1FFFFFFFF2345);
}

TEST_CASE("gdt_limit_zero_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.limit(0));
}

TEST_CASE("gdt_limit_invalid_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.limit(1000));
}

TEST_CASE("gdt_limit_descriptor_success")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    gdt.m_gdt.at(5) = 0xFFF4FFFFFFFF5678;
    CHECK(gdt.limit(5) == 0x0000000045678FFF);
}

TEST_CASE("gdt_limit_descriptor_in_bytes_success")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    gdt.m_gdt.at(5) = 0xFF74FFFFFFFF5678;
    CHECK(gdt.limit(5) == 0x0000000000045678);
}

TEST_CASE("gdt_set_access_rights_zero_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.set_access_rights(0, 0x10));
}

TEST_CASE("gdt_set_access_rights_invalid_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.set_access_rights(1000, 0x10));
}

TEST_CASE("gdt_set_access_rights_descriptor_success")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_NOTHROW(gdt.set_access_rights(5, 0x12345678));
    CHECK(gdt.m_gdt.at(5) == 0xFF5F78FFFFFFFFFF);
}

TEST_CASE("gdt_access_rights_zero_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.access_rights(0));
}

TEST_CASE("gdt_access_rights_invalid_index")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    CHECK_THROWS(gdt.access_rights(1000));
}

TEST_CASE("gdt_access_rights_descriptor_success")
{
    setup_test_support();

    bfvmm::x64::gdt gdt;
    gdt.m_gdt.at(5) = 0xFF5F78FFFFFFFFFF;
    CHECK(gdt.access_rights(5) == 0x0000000000005078);
}
