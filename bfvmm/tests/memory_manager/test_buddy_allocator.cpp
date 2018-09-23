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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-reinterpret-cast
//
// Reason:
//     Although in general this is a good rule, for hypervisor level code that
//     interfaces with the kernel, and raw hardware, this rule is
//     impractical.
//

#include <catch/catch.hpp>

#include <test/support.h>
#include <memory_manager/buddy_allocator.h>

auto k = 3ULL;
auto node_tree_size = buddy_allocator::node_tree_size(k);

TEST_CASE("buddy_allocator: next_power_2")
{
    CHECK(next_power_2(0x1000) == 0x1000);
    CHECK(next_power_2(0x1010) == 0x2000);
    CHECK(next_power_2(0x2000) == 0x2000);
    CHECK(next_power_2(0x3000) == 0x4000);
    CHECK(next_power_2(0x4000) == 0x4000);
    CHECK(next_power_2(0x0700000000000000) == 0x0800000000000000);
    CHECK(next_power_2(0x0800000000000000) == 0x0800000000000000);
}

TEST_CASE("buddy_allocator: buffer_size")
{
    CHECK(buddy_allocator::buffer_size(0) == 0x1000);
    CHECK(buddy_allocator::buffer_size(1) == 0x2000);
    CHECK(buddy_allocator::buffer_size(2) == 0x4000);
}

TEST_CASE("buddy_allocator: node_tree_size")
{
    CHECK(buddy_allocator::node_tree_size(0) == 1 * 32);
    CHECK(buddy_allocator::node_tree_size(1) == 3 * 32);
    CHECK(buddy_allocator::node_tree_size(2) == 7 * 32);
}

TEST_CASE("buddy_allocator: constructor pointer")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator{reinterpret_cast<void *>(0x100000ULL), k, nt.get()};
}

TEST_CASE("buddy_allocator: constructor integer pointer")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator{0x100000ULL, k, nt.get()};
}

TEST_CASE("buddy_allocator: zero allocation")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_THROWS(buddy.allocate(0));
}

TEST_CASE("buddy_allocator: huge allocation")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_THROWS(buddy.allocate(0xFFFFFFFFFFFFFFFF));
}

TEST_CASE("buddy_allocator: unaligned allocation")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(10));
}

TEST_CASE("buddy_allocator: contains")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto addr = buddy.allocate(0x1000);
    CHECK(buddy.contains(addr));
    CHECK(!buddy.contains(reinterpret_cast<void *>(42)));
}

TEST_CASE("buddy_allocator: allocation all 4k blocks")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation all in 8k blocks")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation all in 16k blocks and unalgined")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x3000));
    CHECK_NOTHROW(buddy.allocate(0x4000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation all in 32k blocks")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x8000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 4k / 8k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 8k / 4k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 4k / 8k / 4k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 4k / 8k / 4k / 8k / 4k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 8k / 4k / 8k / 4k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 4k / 16k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x4000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 16k / 4k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x4000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 4k / 16k / 4k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x4000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 4k / 8k / 16k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x4000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 16k / 8k / 4k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x4000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 16k / 4k / 8k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x4000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x2000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation mixed 8k / 16k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x4000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}


TEST_CASE("buddy_allocator: allocation mixed 16k / 8k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x4000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));

    CHECK_THROWS(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation, uneven 4k / 8k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation, uneven 4k / 16k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: allocation, uneven 4k / 32k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_THROWS(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: deallocation nullptr")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    buddy.deallocate(nullptr);
}

TEST_CASE("buddy_allocator: deallocation unaligned")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    buddy.deallocate(reinterpret_cast<void *>(0x100010ULL));
}

TEST_CASE("buddy_allocator: deallocation random")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    buddy.deallocate(reinterpret_cast<void *>(0x123450000ULL));
}

TEST_CASE("buddy_allocator: deallocation unallocated")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    buddy.deallocate(reinterpret_cast<void *>(0x100000ULL));
}

TEST_CASE("buddy_allocator: deallocation twice")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    buddy.deallocate(ptr1);
    buddy.deallocate(ptr1);
}

TEST_CASE("buddy_allocator: deallocation single 4k, allocate single 4k #1")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr1);
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation single 4k, allocate single 4k #2")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr2);
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation single 4k, allocate single 4k #3")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr3);
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation single 4k, allocate single 4k #4")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr4);
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation single 4k, allocate single 4k #5")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr5);
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation single 4k, allocate single 4k #6")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr6);
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation single 4k, allocate single 4k #7")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr7);
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation single 4k, allocate single 4k #8")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr8);
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation double 4k, allocate single 8k #1/2")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    CHECK_NOTHROW(buddy.allocate(0x2000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation double 4k, allocate single 8k #3/4")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    CHECK_NOTHROW(buddy.allocate(0x2000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation double 4k, allocate single 8k #5/6")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    CHECK_NOTHROW(buddy.allocate(0x2000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation double 4k, allocate single 8k #7/8")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
    CHECK_NOTHROW(buddy.allocate(0x2000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation double 4k, allocate single 16k #1/2/3/4")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    CHECK_NOTHROW(buddy.allocate(0x4000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation double 4k, allocate single 16k #5/6/7/8")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
    CHECK_NOTHROW(buddy.allocate(0x4000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation double 4k, allocate single 8k #2/3 fail")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation double 4k, allocate single 8k #4/5 fail")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation double 4k, allocate single 8k #6/7 fail")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    CHECK_THROWS(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation double 4k, allocate single 16k #3/4/5/6")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    CHECK_THROWS(buddy.allocate(0x4000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);
}

TEST_CASE("buddy_allocator: deallocation all 4k, allocate all 4k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);

    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
}

TEST_CASE("buddy_allocator: deallocation all 4k, allocate all 8k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);

    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x2000));
}

TEST_CASE("buddy_allocator: deallocation all 4k, allocate all 16k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);

    CHECK_NOTHROW(buddy.allocate(0x4000));
    CHECK_NOTHROW(buddy.allocate(0x4000));
}

TEST_CASE("buddy_allocator: deallocation all 4k, allocate all 32k")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
    buddy.deallocate(ptr5);
    buddy.deallocate(ptr6);
    buddy.deallocate(ptr7);
    buddy.deallocate(ptr8);

    CHECK_NOTHROW(buddy.allocate(0x8000));
}

TEST_CASE("buddy_allocator: deallocation single 8k, allocate double 4k #1")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x2000);
    auto ptr2 = buddy.allocate(0x2000);
    auto ptr3 = buddy.allocate(0x2000);
    auto ptr4 = buddy.allocate(0x2000);

    buddy.deallocate(ptr1);
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
}

TEST_CASE("buddy_allocator: deallocation single 8k, allocate double 4k #2")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x2000);
    auto ptr2 = buddy.allocate(0x2000);
    auto ptr3 = buddy.allocate(0x2000);
    auto ptr4 = buddy.allocate(0x2000);

    buddy.deallocate(ptr2);
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
}

TEST_CASE("buddy_allocator: deallocation single 8k, allocate double 4k #3")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x2000);
    auto ptr2 = buddy.allocate(0x2000);
    auto ptr3 = buddy.allocate(0x2000);
    auto ptr4 = buddy.allocate(0x2000);

    buddy.deallocate(ptr3);
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
}

TEST_CASE("buddy_allocator: deallocation single 8k, allocate double 4k #4")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x2000);
    auto ptr2 = buddy.allocate(0x2000);
    auto ptr3 = buddy.allocate(0x2000);
    auto ptr4 = buddy.allocate(0x2000);

    buddy.deallocate(ptr4);
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
    buddy.deallocate(ptr3);
    buddy.deallocate(ptr4);
}

TEST_CASE("buddy_allocator: deallocation single 16k, allocate 4k, 8k #1")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x4000);
    auto ptr2 = buddy.allocate(0x4000);

    buddy.deallocate(ptr1);
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
}

TEST_CASE("buddy_allocator: deallocation single 16k, allocate 4k, 8k #2")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x4000);
    auto ptr2 = buddy.allocate(0x4000);

    buddy.deallocate(ptr2);
    CHECK_NOTHROW(buddy.allocate(0x2000));
    CHECK_NOTHROW(buddy.allocate(0x1000));
    CHECK_NOTHROW(buddy.allocate(0x1000));

    buddy.deallocate(ptr1);
    buddy.deallocate(ptr2);
}

TEST_CASE("buddy_allocator: size nullptr")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK(buddy.size(nullptr) == 0);
}

TEST_CASE("buddy_allocator: size unaligned")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK(buddy.size(reinterpret_cast<void *>(0x100010ULL)) == 0);
}

TEST_CASE("buddy_allocator: size random")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK(buddy.size(reinterpret_cast<void *>(0x123450000ULL)) == 0);
}

TEST_CASE("buddy_allocator: size unallocated")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    CHECK(buddy.size(reinterpret_cast<void *>(0x100000ULL)) == 0);
}
TEST_CASE("buddy_allocator: size 4k blocks")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x1000);
    auto ptr2 = buddy.allocate(0x1000);
    auto ptr3 = buddy.allocate(0x1000);
    auto ptr4 = buddy.allocate(0x1000);
    auto ptr5 = buddy.allocate(0x1000);
    auto ptr6 = buddy.allocate(0x1000);
    auto ptr7 = buddy.allocate(0x1000);
    auto ptr8 = buddy.allocate(0x1000);

    CHECK(buddy.size(ptr1) == 0x1000);
    CHECK(buddy.size(ptr2) == 0x1000);
    CHECK(buddy.size(ptr3) == 0x1000);
    CHECK(buddy.size(ptr4) == 0x1000);
    CHECK(buddy.size(ptr5) == 0x1000);
    CHECK(buddy.size(ptr6) == 0x1000);
    CHECK(buddy.size(ptr7) == 0x1000);
    CHECK(buddy.size(ptr8) == 0x1000);
}

TEST_CASE("buddy_allocator: size 8k blocks")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x2000);
    auto ptr2 = buddy.allocate(0x2000);
    auto ptr3 = buddy.allocate(0x2000);
    auto ptr4 = buddy.allocate(0x2000);

    CHECK(buddy.size(ptr1) == 0x2000);
    CHECK(buddy.size(ptr2) == 0x2000);
    CHECK(buddy.size(ptr3) == 0x2000);
    CHECK(buddy.size(ptr4) == 0x2000);
}

TEST_CASE("buddy_allocator: size 16k blocks")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x4000);
    auto ptr2 = buddy.allocate(0x4000);

    CHECK(buddy.size(ptr1) == 0x4000);
    CHECK(buddy.size(ptr2) == 0x4000);
}

TEST_CASE("buddy_allocator: size 32k blocks")
{
    auto nt = std::make_unique<char[]>(node_tree_size);
    buddy_allocator buddy{0x100000ULL, k, nt.get()};

    auto ptr1 = buddy.allocate(0x8000);
    CHECK(buddy.size(ptr1) == 0x8000);
}
