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

#include <test/support.h>
#include <memory_manager/arch/x64/cr3/mmap.h>

using namespace bfvmm::x64;

TEST_CASE("mmap: constructor / destructor")
{
    {
        cr3::mmap mmap{};
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: cr3")
{
    {
        cr3::mmap mmap{};
        CHECK(mmap.cr3() != 0);
        CHECK(mmap.cr3() != 0);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g attribute types")
{
    constexpr auto addr1 = ::x64::pdpt::page_size * 1;
    constexpr auto addr2 = ::x64::pdpt::page_size * 2;
    constexpr auto addr3 = ::x64::pdpt::page_size * 3;

    {
        cr3::mmap mmap{};
        mmap.map_1g(addr1, addr1, cr3::mmap::attr_type::read_write);
        mmap.map_1g(addr2, addr2, cr3::mmap::attr_type::read_execute);
        mmap.map_1g(addr3, addr3, cr3::mmap::attr_type::read_write_execute);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m attribute types")
{
    constexpr auto addr1 = ::x64::pd::page_size * 1;
    constexpr auto addr2 = ::x64::pd::page_size * 2;
    constexpr auto addr3 = ::x64::pd::page_size * 3;

    {
        cr3::mmap mmap{};
        mmap.map_2m(addr1, addr1, cr3::mmap::attr_type::read_write);
        mmap.map_2m(addr2, addr2, cr3::mmap::attr_type::read_execute);
        mmap.map_2m(addr3, addr3, cr3::mmap::attr_type::read_write_execute);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k attribute types")
{
    constexpr auto addr1 = ::x64::pt::page_size * 1;
    constexpr auto addr2 = ::x64::pt::page_size * 2;
    constexpr auto addr3 = ::x64::pt::page_size * 3;

    {
        cr3::mmap mmap{};
        mmap.map_4k(addr1, addr1, cr3::mmap::attr_type::read_write);
        mmap.map_4k(addr2, addr2, cr3::mmap::attr_type::read_execute);
        mmap.map_4k(addr3, addr3, cr3::mmap::attr_type::read_write_execute);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g memory types")
{
    constexpr auto rw = cr3::mmap::attr_type::read_write;
    constexpr auto addr1 = ::x64::pdpt::page_size * 1;
    constexpr auto addr2 = ::x64::pdpt::page_size * 2;

    {
        cr3::mmap mmap{};
        mmap.map_1g(addr1, addr1, rw, cr3::mmap::memory_type::uncacheable);
        mmap.map_1g(addr2, addr2, rw, cr3::mmap::memory_type::write_back);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m memory types")
{
    constexpr auto rw = cr3::mmap::attr_type::read_write;
    constexpr auto addr1 = ::x64::pd::page_size * 1;
    constexpr auto addr2 = ::x64::pd::page_size * 2;

    {
        cr3::mmap mmap{};
        mmap.map_2m(addr1, addr1, rw, cr3::mmap::memory_type::uncacheable);
        mmap.map_2m(addr2, addr2, rw, cr3::mmap::memory_type::write_back);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k memory types")
{
    constexpr auto rw = cr3::mmap::attr_type::read_write;
    constexpr auto addr1 = ::x64::pt::page_size * 1;
    constexpr auto addr2 = ::x64::pt::page_size * 2;

    {
        cr3::mmap mmap{};
        mmap.map_4k(addr1, addr1, rw, cr3::mmap::memory_type::uncacheable);
        mmap.map_4k(addr2, addr2, rw, cr3::mmap::memory_type::write_back);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g twice fails")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
        CHECK_THROWS(mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m twice fails")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
        CHECK_THROWS(mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k twice fails")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
        CHECK_THROWS(mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 1g")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
        mmap.unmap(::x64::pdpt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 2m")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
        mmap.unmap(::x64::pd::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 4k")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
        mmap.unmap(::x64::pt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 1g twice")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
        mmap.unmap(::x64::pdpt::page_size);
        mmap.unmap(::x64::pdpt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 2m twice")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
        mmap.unmap(::x64::pd::page_size);
        mmap.unmap(::x64::pd::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap 4k twice")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
        mmap.unmap(::x64::pt::page_size);
        mmap.unmap(::x64::pt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map / unmap 1g different ranges")
{
    constexpr auto addr1 = ::x64::pdpt::page_size * 1;
    constexpr auto addr2 = ::x64::pdpt::page_size * 2;

    {
        cr3::mmap mmap{};
        mmap.map_1g(addr1, addr1);
        mmap.map_1g(addr2, addr2);
        mmap.unmap(addr1);
        mmap.unmap(addr2);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map / unmap 2m different ranges")
{
    constexpr auto addr1 = ::x64::pd::page_size * 1;
    constexpr auto addr2 = ::x64::pd::page_size * 2;

    {
        cr3::mmap mmap{};
        mmap.map_2m(addr1, addr1);
        mmap.map_2m(addr2, addr2);
        mmap.unmap(addr1);
        mmap.unmap(addr2);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map / unmap 4k different ranges")
{
    constexpr auto addr1 = ::x64::pt::page_size * 1;
    constexpr auto addr2 = ::x64::pt::page_size * 2;

    {
        cr3::mmap mmap{};
        mmap.map_4k(addr1, addr1);
        mmap.map_4k(addr2, addr2);
        mmap.unmap(addr1);
        mmap.unmap(addr2);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap non-mapped address")
{
    {
        cr3::mmap mmap{};
        mmap.unmap(::x64::pdpt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap non-mapped address 1g")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(nullptr, 0);
        mmap.unmap(::x64::pdpt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: unmap non-mapped address 2m")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(nullptr, 0);
        mmap.unmap(::x64::pd::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g twice with unmap succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
        mmap.unmap(::x64::pdpt::page_size);
        mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m twice with unmap succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
        mmap.unmap(::x64::pd::page_size);
        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k twice with unmap succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
        mmap.unmap(::x64::pt::page_size);
        mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: release 1g")
{
    cr3::mmap mmap{};
    mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
    mmap.release(::x64::pdpt::page_size);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 2m")
{
    cr3::mmap mmap{};
    mmap.map_2m(::x64::pdpt::page_size, ::x64::pdpt::page_size);
    mmap.release(::x64::pdpt::page_size);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 4k")
{
    cr3::mmap mmap{};
    mmap.map_4k(::x64::pdpt::page_size, ::x64::pdpt::page_size);
    mmap.release(::x64::pdpt::page_size);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 1g twice")
{
    cr3::mmap mmap{};
    mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
    mmap.release(::x64::pdpt::page_size);
    mmap.release(::x64::pdpt::page_size);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 2m twice")
{
    cr3::mmap mmap{};
    mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
    mmap.release(::x64::pd::page_size);
    mmap.release(::x64::pd::page_size);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release 4k twice")
{
    cr3::mmap mmap{};
    mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
    mmap.release(::x64::pt::page_size);
    mmap.release(::x64::pt::page_size);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release non-mapped address")
{
    cr3::mmap mmap{};
    mmap.release(::x64::pt::page_size);
    CHECK(g_allocated_pages.size() == 1);
}

TEST_CASE("mmap: release non-mapped address 1g")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(nullptr, 0);
        mmap.release(::x64::pdpt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: release non-mapped address 2m")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(nullptr, 0);
        mmap.release(::x64::pd::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g twice with release succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
        mmap.release(::x64::pdpt::page_size);
        mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m twice with release succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
        mmap.release(::x64::pd::page_size);
        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k twice with release succeeds")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
        mmap.release(::x64::pt::page_size);
        mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map twice, release once")
{
    constexpr auto addr1 = ::x64::pt::page_size * 1;
    constexpr auto addr2 = ::x64::pt::page_size * 2;

    {
        cr3::mmap mmap{};

        mmap.map_4k(addr1, addr1);
        mmap.map_4k(addr2, addr2);
        mmap.release(addr2);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g, entry")
{
    {
        cr3::mmap mmap{};

        mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
        CHECK_NOTHROW(mmap.entry(::x64::pdpt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m, entry")
{
    {
        cr3::mmap mmap{};

        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
        CHECK_NOTHROW(mmap.entry(::x64::pd::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k, entry")
{
    {
        cr3::mmap mmap{};

        mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
        CHECK_NOTHROW(mmap.entry(::x64::pt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: entry non-mapped address")
{
    {
        cr3::mmap mmap{};
        CHECK_THROWS(mmap.entry(::x64::pt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: entry non-mapped address 1g")
{
    {
        cr3::mmap mmap{};

        mmap.map_1g(nullptr, 0);
        CHECK_THROWS(mmap.entry(::x64::pdpt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: entry non-mapped address 2m")
{
    {
        cr3::mmap mmap{};

        mmap.map_2m(nullptr, 0);
        CHECK_THROWS(mmap.entry(::x64::pd::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: entry non-mapped address 4k")
{
    {
        cr3::mmap mmap{};

        mmap.map_4k(nullptr, 0);
        CHECK_THROWS(mmap.entry(::x64::pt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g, virt_to_phys")
{
    constexpr auto addr1 = ::x64::pdpt::page_size * 1;
    constexpr auto addr2 = ::x64::pdpt::page_size * 1 + 42;

    {
        cr3::mmap mmap{};

        mmap.map_1g(addr1, addr1);
        CHECK(mmap.virt_to_phys(addr1).first == addr1);
        CHECK(mmap.virt_to_phys(addr2).first == addr2);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m, virt_to_phys")
{
    constexpr auto addr1 = ::x64::pd::page_size * 1;
    constexpr auto addr2 = ::x64::pd::page_size * 1 + 42;

    {
        cr3::mmap mmap{};

        mmap.map_2m(addr1, addr1);
        CHECK(mmap.virt_to_phys(addr1).first == addr1);
        CHECK(mmap.virt_to_phys(addr2).first == addr2);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k, virt_to_phys")
{
    constexpr auto addr1 = ::x64::pt::page_size * 1;
    constexpr auto addr2 = ::x64::pt::page_size * 1 + 42;

    {
        cr3::mmap mmap{};

        mmap.map_4k(addr1, addr1);
        CHECK(mmap.virt_to_phys(addr1).first == addr1);
        CHECK(mmap.virt_to_phys(addr2).first == addr2);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: virt_to_phys non-mapped address")
{
    {
        cr3::mmap mmap{};
        CHECK_THROWS(mmap.virt_to_phys(::x64::pt::page_size).first);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: virt_to_phys non-mapped address 1g")
{
    {
        cr3::mmap mmap{};

        mmap.map_1g(nullptr, 0);
        CHECK_THROWS(mmap.virt_to_phys(::x64::pdpt::page_size).first);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: virt_to_phys non-mapped address 2m")
{
    {
        cr3::mmap mmap{};

        mmap.map_2m(nullptr, 0);
        CHECK_THROWS(mmap.virt_to_phys(::x64::pd::page_size).first);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: virt_to_phys non-mapped address 4k")
{
    {
        cr3::mmap mmap{};

        mmap.map_4k(nullptr, 0);
        CHECK_THROWS(mmap.virt_to_phys(::x64::pt::page_size).first);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 1g, from")
{
    {
        cr3::mmap mmap{};

        mmap.map_1g(::x64::pdpt::page_size, ::x64::pdpt::page_size);
        CHECK(mmap.from(::x64::pdpt::page_size) == ::x64::pdpt::from);
        CHECK(mmap.is_1g(::x64::pdpt::page_size));
        CHECK(!mmap.is_2m(::x64::pdpt::page_size));
        CHECK(!mmap.is_4k(::x64::pdpt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 2m, from")
{
    {
        cr3::mmap mmap{};

        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
        CHECK(mmap.from(::x64::pd::page_size) == ::x64::pd::from);
        CHECK(!mmap.is_1g(::x64::pd::page_size));
        CHECK(mmap.is_2m(::x64::pd::page_size));
        CHECK(!mmap.is_4k(::x64::pd::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: map 4k, from")
{
    {
        cr3::mmap mmap{};

        mmap.map_4k(::x64::pt::page_size, ::x64::pt::page_size);
        CHECK(mmap.from(::x64::pt::page_size) == ::x64::pt::from);
        CHECK(!mmap.is_1g(::x64::pt::page_size));
        CHECK(!mmap.is_2m(::x64::pt::page_size));
        CHECK(mmap.is_4k(::x64::pt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: from non-mapped address")
{
    {
        cr3::mmap mmap{};
        CHECK_THROWS(mmap.from(::x64::pt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: from non-mapped address 1g")
{
    {
        cr3::mmap mmap{};

        mmap.map_1g(nullptr, 0);
        CHECK_THROWS(mmap.from(::x64::pdpt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: from non-mapped address 2m")
{
    {
        cr3::mmap mmap{};

        mmap.map_2m(nullptr, 0);
        CHECK_THROWS(mmap.from(::x64::pd::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: from non-mapped address 4k")
{
    {
        cr3::mmap mmap{};

        mmap.map_4k(nullptr, 0);
        CHECK_THROWS(mmap.from(::x64::pt::page_size));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: remap 2m to 4k")
{
    {
        cr3::mmap mmap{};
        mmap.map_4k(::x64::pd::page_size, ::x64::pd::page_size);
        mmap.release(::x64::pd::page_size);
        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("mmap: remap 4k to 2m")
{
    {
        cr3::mmap mmap{};
        mmap.map_2m(::x64::pd::page_size, ::x64::pd::page_size);
        mmap.release(::x64::pd::page_size);
        mmap.map_4k(::x64::pd::page_size, ::x64::pd::page_size);
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
