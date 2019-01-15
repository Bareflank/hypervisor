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
#include <bfdebug.h>

TEST_CASE("__BFFUNC__")
{
    std::cout << __BFFUNC__ << '\n';
}

TEST_CASE("view_as_pointer: integer")
{
    int i = 1;
    CHECK(view_as_pointer(i) == reinterpret_cast<const void *>(0x1));
}

TEST_CASE("view_as_pointer: pointer")
{
    int i = 1;
    CHECK(view_as_pointer(&i) == reinterpret_cast<const void *>(&i));
}

TEST_CASE("debug macros")
{
    int i = 0;

    bfdebug_lnbr(0);
    bfdebug_brk1(0);
    bfdebug_brk2(0);
    bfdebug_brk3(0);
    bfdebug_nhex(0, "test", 42);
    bfdebug_subnhex(0, "test", 42);
    bfdebug_nhex(0, "test", &i);
    bfdebug_subnhex(0, "test", &i);
    bfdebug_ndec(0, "test", 42);
    bfdebug_subndec(0, "test", 42);
    bfdebug_bool(0, "test", true);
    bfdebug_subbool(0, "test", true);
    bfdebug_bool(0, "test", false);
    bfdebug_subbool(0, "test", false);
    bfdebug_text(0, "test", "value");
    bfdebug_subtext(0, "test", "value");
    bfdebug_info(0, "test");
    bfdebug_pass(0, "test");
    bfdebug_subpass(0, "test");
    bfdebug_fail(0, "test");
    bfdebug_subfail(0, "test");
    bfdebug_test(0, "test", true);
    bfdebug_subtest(0, "test", true);
    bfdebug_test(0, "test", false);
    bfdebug_subtest(0, "test", false);
}

TEST_CASE("debug macros: no print")
{
    bfdebug_lnbr(1000);
    bfdebug_brk1(1000);
    bfdebug_brk2(1000);
    bfdebug_brk3(1000);
    bfdebug_nhex(1000, "test", 42);
    bfdebug_subnhex(1000, "test", 42);
    bfdebug_ndec(1000, "test", 42);
    bfdebug_subndec(1000, "test", 42);
    bfdebug_bool(1000, "test", true);
    bfdebug_subbool(1000, "test", true);
    bfdebug_bool(1000, "test", false);
    bfdebug_subbool(1000, "test", false);
    bfdebug_text(1000, "test", "value");
    bfdebug_subtext(1000, "test", "value");
    bfdebug_info(1000, "test");
    bfdebug_pass(1000, "test");
    bfdebug_subpass(1000, "test");
    bfdebug_fail(1000, "test");
    bfdebug_subfail(1000, "test");
    bfdebug_test(1000, "test", true);
    bfdebug_subtest(1000, "test", true);
    bfdebug_test(1000, "test", false);
    bfdebug_subtest(1000, "test", false);
}

TEST_CASE("alert macros")
{
    int i = 0;

    bfalert_lnbr(0);
    bfalert_brk1(0);
    bfalert_brk2(0);
    bfalert_brk3(0);
    bfalert_nhex(0, "test", 42);
    bfalert_subnhex(0, "test", 42);
    bfalert_nhex(0, "test", &i);
    bfalert_subnhex(0, "test", &i);
    bfalert_ndec(0, "test", 42);
    bfalert_subndec(0, "test", 42);
    bfalert_bool(0, "test", true);
    bfalert_subbool(0, "test", true);
    bfalert_bool(0, "test", false);
    bfalert_subbool(0, "test", false);
    bfalert_text(0, "test", "value");
    bfalert_subtext(0, "test", "value");
    bfalert_info(0, "test");
    bfalert_pass(0, "test");
    bfalert_subpass(0, "test");
    bfalert_fail(0, "test");
    bfalert_subfail(0, "test");
    bfalert_test(0, "test", true);
    bfalert_subtest(0, "test", true);
    bfalert_test(0, "test", false);
    bfalert_subtest(0, "test", false);
}

TEST_CASE("alert macros: no print")
{
    bfalert_lnbr(1000);
    bfalert_brk1(1000);
    bfalert_brk2(1000);
    bfalert_brk3(1000);
    bfalert_nhex(1000, "test", 42);
    bfalert_subnhex(1000, "test", 42);
    bfalert_ndec(1000, "test", 42);
    bfalert_subndec(1000, "test", 42);
    bfalert_bool(1000, "test", true);
    bfalert_subbool(1000, "test", true);
    bfalert_bool(1000, "test", false);
    bfalert_subbool(1000, "test", false);
    bfalert_text(1000, "test", "value");
    bfalert_subtext(1000, "test", "value");
    bfalert_info(1000, "test");
    bfalert_pass(1000, "test");
    bfalert_subpass(1000, "test");
    bfalert_fail(1000, "test");
    bfalert_subfail(1000, "test");
    bfalert_test(1000, "test", true);
    bfalert_subtest(1000, "test", true);
    bfalert_test(1000, "test", false);
    bfalert_subtest(1000, "test", false);
}

TEST_CASE("error macros")
{
    int i = 0;

    bferror_lnbr(0);
    bferror_brk1(0);
    bferror_brk2(0);
    bferror_brk3(0);
    bferror_nhex(0, "test", 42);
    bferror_subnhex(0, "test", 42);
    bferror_nhex(0, "test", &i);
    bferror_subnhex(0, "test", &i);
    bferror_ndec(0, "test", 42);
    bferror_subndec(0, "test", 42);
    bferror_bool(0, "test", true);
    bferror_subbool(0, "test", true);
    bferror_bool(0, "test", false);
    bferror_subbool(0, "test", false);
    bferror_text(0, "test", "value");
    bferror_subtext(0, "test", "value");
    bferror_info(0, "test");
    bferror_pass(0, "test");
    bferror_subpass(0, "test");
    bferror_fail(0, "test");
    bferror_subfail(0, "test");
    bferror_test(0, "test", true);
    bferror_subtest(0, "test", true);
    bferror_test(0, "test", false);
    bferror_subtest(0, "test", false);
}

TEST_CASE("error macros: no print")
{
    bferror_lnbr(1000);
    bferror_brk1(1000);
    bferror_brk2(1000);
    bferror_brk3(1000);
    bferror_nhex(1000, "test", 42);
    bferror_subnhex(1000, "test", 42);
    bferror_ndec(1000, "test", 42);
    bferror_subndec(1000, "test", 42);
    bferror_bool(1000, "test", true);
    bferror_subbool(1000, "test", true);
    bferror_bool(1000, "test", false);
    bferror_subbool(1000, "test", false);
    bferror_text(1000, "test", "value");
    bferror_subtext(1000, "test", "value");
    bferror_info(1000, "test");
    bferror_pass(1000, "test");
    bferror_subpass(1000, "test");
    bferror_fail(1000, "test");
    bferror_subfail(1000, "test");
    bferror_test(1000, "test", true);
    bferror_subtest(1000, "test", true);
    bferror_test(1000, "test", false);
    bferror_subtest(1000, "test", false);
}

TEST_CASE("null tests")
{
    bfdebug_nhex(0, nullptr, 42);
    bfdebug_subnhex(0, nullptr, 42);
    bfdebug_ndec(0, nullptr, 42);
    bfdebug_subndec(0, nullptr, 42);
    bfdebug_bool(0, nullptr, true);
    bfdebug_subbool(0, nullptr, true);
    bfdebug_bool(0, nullptr, false);
    bfdebug_subbool(0, nullptr, false);
    bfdebug_text(0, nullptr, nullptr);
    bfdebug_subtext(0, nullptr, nullptr);
    bfdebug_info(0, nullptr);
    bfdebug_pass(0, nullptr);
    bfdebug_subpass(0, nullptr);
    bfdebug_fail(0, nullptr);
    bfdebug_subfail(0, nullptr);
    bfdebug_test(0, nullptr, true);
    bfdebug_subtest(0, nullptr, true);
    bfdebug_test(0, nullptr, false);
    bfdebug_subtest(0, nullptr, false);
}

TEST_CASE("transaction")
{
    int i = 0;

    bfdebug_transaction(0, [&](std::string * msg) {
        bfdebug_lnbr(0, msg);
        bfdebug_brk1(0, msg);
        bfdebug_brk2(0, msg);
        bfdebug_brk3(0, msg);
        bfdebug_nhex(0, "test", 42, msg);
        bfdebug_subnhex(0, "test", 42, msg);
        bfdebug_nhex(0, "test", &i, msg);
        bfdebug_subnhex(0, "test", &i, msg);
        bfdebug_ndec(0, "test", 42, msg);
        bfdebug_subndec(0, "test", 42, msg);
        bfdebug_bool(0, "test", true, msg);
        bfdebug_subbool(0, "test", true, msg);
        bfdebug_bool(0, "test", false, msg);
        bfdebug_subbool(0, "test", false, msg);
        bfdebug_text(0, "test", "value", msg);
        bfdebug_subtext(0, "test", "value", msg);
        bfdebug_info(0, "test", msg);
        bfdebug_pass(0, "test", msg);
        bfdebug_subpass(0, "test", msg);
        bfdebug_fail(0, "test", msg);
        bfdebug_subfail(0, "test", msg);
        bfdebug_test(0, "test", true, msg);
        bfdebug_subtest(0, "test", true, msg);
        bfdebug_test(0, "test", false, msg);
        bfdebug_subtest(0, "test", false, msg);

        for (auto j = 0; j < 0x1000; j++) {
            bfdebug_info(0, "the cow is blue", msg);
        }
    });
}

TEST_CASE("debug facilities")
{
    bfline;
    bffield(42);
    bffield_hex(42);
}
