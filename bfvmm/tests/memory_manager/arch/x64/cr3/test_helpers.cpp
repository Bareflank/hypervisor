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
#include <memory_manager/arch/x64/cr3.h>

using namespace bfvmm::x64;

TEST_CASE("identity_map_1g")
{
    cr3::mmap mmap{};
    identity_map_1g(mmap, 0, ::x64::pdpt::page_size * 4);

    CHECK(mmap.is_1g(::x64::pdpt::page_size * 0));
    CHECK(mmap.is_1g(::x64::pdpt::page_size * 1));
    CHECK(mmap.is_1g(::x64::pdpt::page_size * 2));
    CHECK(mmap.is_1g(::x64::pdpt::page_size * 3));
    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 4));
}

TEST_CASE("identity_map_2m")
{
    cr3::mmap mmap{};
    identity_map_2m(mmap, 0, ::x64::pd::page_size * 4);

    CHECK(mmap.is_2m(::x64::pd::page_size * 0));
    CHECK(mmap.is_2m(::x64::pd::page_size * 1));
    CHECK(mmap.is_2m(::x64::pd::page_size * 2));
    CHECK(mmap.is_2m(::x64::pd::page_size * 3));
    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 4));
}

TEST_CASE("identity_map_4k")
{
    cr3::mmap mmap{};
    identity_map_4k(mmap, 0, ::x64::pt::page_size * 4);

    CHECK(mmap.is_4k(::x64::pt::page_size * 0));
    CHECK(mmap.is_4k(::x64::pt::page_size * 1));
    CHECK(mmap.is_4k(::x64::pt::page_size * 2));
    CHECK(mmap.is_4k(::x64::pt::page_size * 3));
    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 4));
}

TEST_CASE("identity_unmap_1g")
{
    cr3::mmap mmap{};
    identity_map_1g(mmap, 0, ::x64::pdpt::page_size * 4);
    identity_unmap_1g(mmap, 0, ::x64::pdpt::page_size * 4);

    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 0));
    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 1));
    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 2));
    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 3));
    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 4));
}

TEST_CASE("identity_unmap_2m")
{
    cr3::mmap mmap{};
    identity_map_2m(mmap, 0, ::x64::pd::page_size * 4);
    identity_unmap_2m(mmap, 0, ::x64::pd::page_size * 4);

    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 0));
    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 1));
    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 2));
    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 3));
    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 4));
}

TEST_CASE("identity_unmap_4k")
{
    cr3::mmap mmap{};
    identity_map_4k(mmap, 0, ::x64::pt::page_size * 4);
    identity_unmap_4k(mmap, 0, ::x64::pt::page_size * 4);

    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 0));
    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 1));
    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 2));
    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 3));
    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 4));
}

TEST_CASE("identity_release_1g")
{
    cr3::mmap mmap{};
    identity_map_1g(mmap, 0, ::x64::pdpt::page_size * 4);
    identity_release_1g(mmap, 0, ::x64::pdpt::page_size * 4);

    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 0));
    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 1));
    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 2));
    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 3));
    CHECK_THROWS(mmap.is_1g(::x64::pdpt::page_size * 4));
}

TEST_CASE("identity_release_2m")
{
    cr3::mmap mmap{};
    identity_map_2m(mmap, 0, ::x64::pd::page_size * 4);
    identity_release_2m(mmap, 0, ::x64::pd::page_size * 4);

    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 0));
    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 1));
    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 2));
    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 3));
    CHECK_THROWS(mmap.is_2m(::x64::pd::page_size * 4));
}

TEST_CASE("identity_release_4k")
{
    cr3::mmap mmap{};
    identity_map_4k(mmap, 0, ::x64::pt::page_size * 4);
    identity_release_4k(mmap, 0, ::x64::pt::page_size * 4);

    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 0));
    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 1));
    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 2));
    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 3));
    CHECK_THROWS(mmap.is_4k(::x64::pt::page_size * 4));
}

TEST_CASE("identity_map_convert_1g_to_2m")
{
    cr3::mmap mmap{};
    identity_map_1g(mmap, 0, ::x64::pdpt::page_size * 4);

    identity_map_convert_1g_to_2m(mmap, 0);
    CHECK(mmap.is_2m(nullptr));
    CHECK(mmap.is_2m(::x64::pdpt::page_size - ::x64::pd::page_size));

    identity_map_convert_2m_to_1g(mmap, 0);
    CHECK(mmap.is_1g(nullptr));
    CHECK(mmap.is_1g(::x64::pdpt::page_size - ::x64::pd::page_size));
}

TEST_CASE("identity_map_convert_1g_to_4k")
{
    cr3::mmap mmap{};
    identity_map_1g(mmap, 0, ::x64::pdpt::page_size * 4);

    identity_map_convert_1g_to_4k(mmap, 0);
    CHECK(mmap.is_4k(nullptr));
    CHECK(mmap.is_4k(::x64::pdpt::page_size - ::x64::pd::page_size));

    identity_map_convert_4k_to_1g(mmap, 0);
    CHECK(mmap.is_1g(nullptr));
    CHECK(mmap.is_1g(::x64::pdpt::page_size - ::x64::pd::page_size));
}

TEST_CASE("identity_map_convert_2m_to_4k")
{
    cr3::mmap mmap{};
    identity_map_2m(mmap, 0, ::x64::pd::page_size * 4);

    identity_map_convert_2m_to_4k(mmap, 0);
    CHECK(mmap.is_4k(nullptr));
    CHECK(mmap.is_4k(::x64::pd::page_size - ::x64::pt::page_size));

    identity_map_convert_4k_to_2m(mmap, 0);
    CHECK(mmap.is_2m(nullptr));
    CHECK(mmap.is_2m(::x64::pd::page_size - ::x64::pt::page_size));
}
