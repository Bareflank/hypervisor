//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

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
