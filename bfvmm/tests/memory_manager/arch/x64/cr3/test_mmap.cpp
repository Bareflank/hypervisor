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
#include <memory_manager/arch/x64/cr3/mmap.h>

using namespace bfvmm::x64;

TEST_CASE("quiet")
{
    unsafe_write_cstr("", 0);
}

TEST_CASE("mmap: constructor / destructor")
{
    {
        cr3::mmap mmap{};
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g RE")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_execute);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m RE")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_execute);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k RE")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_execute);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g twice fails")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        CHECK_THROWS(mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m twice fails")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        CHECK_THROWS(mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k twice fails")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        CHECK_THROWS(mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write));
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 1g")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 2m")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 4k")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 1g twice")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 2m twice")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 4k twice")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map / unmap 1g different ranges")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.map_1g(0x8000002A, 0x8000002A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
        mmap.unmap(0x8000002A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map / unmap 2m different ranges")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.map_2m(0x8000002A, 0x8000002A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
        mmap.unmap(0x8000002A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map / unmap 4k different ranges")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.map_4k(0x8000002A, 0x8000002A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
        mmap.unmap(0x8000002A);
    }
    CHECK(g_allocated_pages.empty());
}
TEST_CASE("mmap: unmap non-mapped address")
{
    {
        cr3::mmap mmap{};
        mmap.unmap(0x2A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g twice with unmap succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
        mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m twice with unmap succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
        mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k twice with unmap succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.unmap(0x2A);
        mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: release 1g")
{
    cr3::mmap mmap{};
    mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 2m")
{
    cr3::mmap mmap{};
    mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 4k")
{
    cr3::mmap mmap{};
    mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 1g twice")
{
    cr3::mmap mmap{};
    mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    mmap.release(0x2A);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 2m twice")
{
    cr3::mmap mmap{};
    mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    mmap.release(0x2A);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 4k twice")
{
    cr3::mmap mmap{};
    mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    mmap.release(0x2A);
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release non-mapped address")
{
    cr3::mmap mmap{};
    mmap.release(0x2A);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: map 1g twice with release succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.release(0x2A);
        mmap.map_1g(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m twice with release succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.release(0x2A);
        mmap.map_2m(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k twice with release succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.release(0x2A);
        mmap.map_4k(0x2A, 0x2A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map twise, release once")
{
    {
        cr3::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.map_4k(0x202A, 0x202A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.release(0x202A);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g, virt_to_phys")
{
    {
        cr3::mmap mmap{};

        mmap.map_1g(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        CHECK(mmap.virt_to_phys(0x2A) == 0x1000);
        CHECK(mmap.virt_to_phys(0x100000) == 0x1000);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m, virt_to_phys")
{
    {
        cr3::mmap mmap{};

        mmap.map_2m(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        CHECK(mmap.virt_to_phys(0x102A) == 0x1000);
        CHECK(mmap.virt_to_phys(0x10000) == 0x1000);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k, virt_to_phys")
{
    {
        cr3::mmap mmap{};

        mmap.map_4k(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        CHECK(mmap.virt_to_phys(0x102A) == 0x1000);
        CHECK(mmap.virt_to_phys(0x1000) == 0x1000);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: virt_to_phys non-mapped address")
{
    {
        cr3::mmap mmap{};
        CHECK(mmap.virt_to_phys(0x102A) == 0x0);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: virt_to_phys after unmap")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        CHECK(mmap.virt_to_phys(0x102A) == 0x1000);
        mmap.unmap(0x102A);
        CHECK(mmap.virt_to_phys(0x102A) == 0x0);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: mdl")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        CHECK(mmap.mdl().size() == 4);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: mdl after release")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.release(0x102A);
        CHECK(mmap.mdl().size() == 1);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: remap 2m to 4k")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.release(0x102A);
        mmap.map_2m(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: remap 4k to 2m")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
        mmap.release(0x102A);
        mmap.map_4k(0x102A, 0x102A, bfvmm::x64::cr3::mmap::attr_type::read_write);
    }
    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: 1g release desperate pages")
{
    cr3::mmap mmap{};
    mmap.map_1g(0x40000000, 0x40000000);
    mmap.map_1g(0x1000000000, 0x1000000000);
    mmap.map_1g(0x200000000000, 0x200000000000);
    mmap.map_1g(0x40000000000000, 0x40000000000000);
    mmap.release(0x40000000);
    mmap.release(0x1000000000);
    mmap.release(0x200000000000);
    mmap.release(0x40000000000000);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: 2m release desperate pages")
{
    cr3::mmap mmap{};
    mmap.map_2m(0x200000, 0x200000);
    mmap.map_2m(0x40000000, 0x40000000);
    mmap.map_2m(0x1000000000, 0x1000000000);
    mmap.map_2m(0x200000000000, 0x200000000000);
    mmap.map_2m(0x40000000000000, 0x40000000000000);
    mmap.release(0x200000);
    mmap.release(0x40000000);
    mmap.release(0x1000000000);
    mmap.release(0x200000000000);
    mmap.release(0x40000000000000);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: 4k release desperate pages")
{
    cr3::mmap mmap{};
    mmap.map_4k(0x1000, 0x1000);
    mmap.map_4k(0x200000, 0x200000);
    mmap.map_4k(0x40000000, 0x40000000);
    mmap.map_4k(0x1000000000, 0x1000000000);
    mmap.map_4k(0x200000000000, 0x200000000000);
    mmap.map_4k(0x40000000000000, 0x40000000000000);
    mmap.release(0x1000);
    mmap.release(0x200000);
    mmap.release(0x40000000);
    mmap.release(0x1000000000);
    mmap.release(0x200000000000);
    mmap.release(0x40000000000000);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: 1g release range")
{
    cr3::mmap mmap{};
    mmap.map_1g(0x40000000, 0x40000000);
    mmap.map_1g(0x80000000, 0x80000000);
    mmap.map_1g(0xC0000000, 0xC0000000);
    mmap.release(0x40000000);
    mmap.release(0x80000000);
    mmap.release(0xC0000000);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: 2m release range")
{
    cr3::mmap mmap{};
    mmap.map_2m(0x200000, 0x200000);
    mmap.map_2m(0x400000, 0x400000);
    mmap.map_2m(0x600000, 0x600000);
    mmap.release(0x200000);
    mmap.release(0x400000);
    mmap.release(0x600000);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: 4k release range")
{
    cr3::mmap mmap{};
    mmap.map_4k(0x1000, 0x1000);
    mmap.map_4k(0x2000, 0x2000);
    mmap.map_4k(0x3000, 0x3000);
    mmap.release(0x1000);
    mmap.release(0x2000);
    mmap.release(0x3000);
    CHECK(g_allocated_pages.size() == 1);
}
