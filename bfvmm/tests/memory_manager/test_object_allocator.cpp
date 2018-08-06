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

// TIDY_EXCLUSION=-cppcoreguidelines-owning-memory
//
// Reason:
//     This test triggers false positives during testing when attempting to
//     transfer ownership, which is currently a known issue
//
//     https://clang.llvm.org/extra/clang-tidy/checks/
//     cppcoreguidelines-owning-memory.html
//

#include <catch/catch.hpp>

#include <list>
#include <queue>
#include <memory>

#include <test/support.h>
#include <memory_manager/object_allocator.h>

constexpr const auto blocks_per_page = 512;

TEST_CASE("basic allocator of 0 size")
{
    basic_object_allocator pool{0, 0};
}

TEST_CASE("basic allocator size")
{
    basic_object_allocator pool{sizeof(uint64_t), 0};
    CHECK(pool.size(nullptr) == sizeof(uint64_t));
}

TEST_CASE("construction: limited")
{
    {
        object_allocator<uint64_t, 1> pool{};

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page);
        CHECK(pool.num_used() == 0);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("construction: limited out of memory")
{
    g_out_of_memory = true;
    auto ___ = gsl::finally([] {
        g_out_of_memory = false;
    });

    {
        object_allocator<uint64_t, 1> pool1{};
        object_allocator<uint64_t, 0> pool2{};

        CHECK_THROWS(pool2.allocate(1));
    }
}

TEST_CASE("construction: unlimited")
{
    {
        object_allocator<uint64_t> pool{};

        CHECK(pool.page_stack_size() == 0);
        CHECK(pool.objt_stack_size() == 0);
        CHECK(pool.num_page() == 0);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 0);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("allocate: single allocation")
{
    {
        object_allocator<uint64_t> pool{};

        auto ptr = pool.allocate(1);
        CHECK_NOTHROW(ptr);

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page - 1);
        CHECK(pool.num_used() == 1);

        pool.deallocate(ptr, 1);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("allocate: single allocation without free")
{
    {
        object_allocator<uint64_t> pool{};

        CHECK_NOTHROW(pool.allocate(1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page - 1);
        CHECK(pool.num_used() == 1);
    }

    CHECK(!g_allocated_pages.empty());

    auto pages = g_allocated_pages;
    for (const auto &ptr : pages) {
        free_page(ptr);
    }

    g_allocated_pages.clear();
}

TEST_CASE("allocate: single allocation n != 1")
{
    {
        object_allocator<uint64_t> pool{};

        auto ptr = pool.allocate(10);
        CHECK_NOTHROW(ptr);

        CHECK(pool.page_stack_size() == 0);
        CHECK(pool.objt_stack_size() == 0);
        CHECK(pool.num_page() == 0);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 0);

        pool.deallocate(ptr, 10);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("allocate: multiple allocations")
{
    {
        object_allocator<uint64_t> pool{};

        for (auto i = 0; i < blocks_per_page * 4; i++) {
            pool.allocate(1);
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 9);
        CHECK(pool.num_page() == 4);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == blocks_per_page * 4);
    }

    CHECK(!g_allocated_pages.empty());

    auto pages = g_allocated_pages;
    for (const auto &ptr : pages) {
        free_page(ptr);
    }

    g_allocated_pages.clear();
}

TEST_CASE("allocate: multiple allocations with odd sized T")
{
    {
        struct test {
            uint64_t val1;
            uint64_t val2;
            uint64_t val3;
        };

        object_allocator<test> pool{};

        for (auto i = 0U; i < 0x1000U / sizeof(test); i++) {
            CHECK_NOTHROW(pool.allocate(1));
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 1);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 0x1000U / sizeof(test));

        CHECK_NOTHROW(pool.allocate(1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 2);
        CHECK(pool.num_page() == 2);
        CHECK(pool.num_free() == (0x1000U / sizeof(test)) - 1);
        CHECK(pool.num_used() == (0x1000U / sizeof(test)) + 1);
    }

    CHECK(!g_allocated_pages.empty());

    auto pages = g_allocated_pages;
    for (const auto &ptr : pages) {
        free_page(ptr);
    }

    g_allocated_pages.clear();
}

TEST_CASE("allocate: over limit")
{
    {
        object_allocator<uint64_t, 1> pool{};

        for (auto i = 0; i < blocks_per_page; i++) {
            pool.allocate(1);
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == blocks_per_page);

        CHECK_THROWS(pool.allocate(1));
    }

    CHECK(!g_allocated_pages.empty());

    auto pages = g_allocated_pages;
    for (const auto &ptr : pages) {
        free_page(ptr);
    }

    g_allocated_pages.clear();
}

TEST_CASE("deallocate: deallocate without allocate")
{
    {
        uint64_t nothing = 0;
        object_allocator<uint64_t> pool{};

        CHECK_NOTHROW(pool.deallocate(&nothing, 1));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("deallocate: deallocate single allocation")
{
    {
        object_allocator<uint64_t> pool{};

        auto alloc = pool.allocate(1);

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page - 1);
        CHECK(pool.num_used() == 1);

        CHECK_NOTHROW(pool.deallocate(alloc, 1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page);
        CHECK(pool.num_used() == 0);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("deallocate: deallocate multiple allocations")
{
    {
        std::list<uint64_t *> v{};
        object_allocator<uint64_t> pool{};

        for (auto i = 0; i < blocks_per_page * 4; i++) {
            v.push_back(pool.allocate(1));
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 9);
        CHECK(pool.num_page() == 4);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == blocks_per_page * 4);

        for (auto elem : v) {
            pool.deallocate(elem, 1);
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 9);
        CHECK(pool.num_page() == 4);
        CHECK(pool.num_free() == blocks_per_page * 4);
        CHECK(pool.num_used() == 0);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("max_size: can allocate max_size")
{
    {
        object_allocator<__oa_page> pool{};

        CHECK_NOTHROW(pool.allocate(1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 1);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 1);
    }

    CHECK(!g_allocated_pages.empty());

    auto pages = g_allocated_pages;
    for (const auto &ptr : pages) {
        free_page(ptr);
    }

    g_allocated_pages.clear();
}

TEST_CASE("max_size: can allocate max_size more than once")
{
    {
        object_allocator<__oa_page> pool{};

        CHECK_NOTHROW(pool.allocate(1));
        CHECK_NOTHROW(pool.allocate(1));
        CHECK_NOTHROW(pool.allocate(1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 1);
        CHECK(pool.num_page() == 3);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 3);
    }

    CHECK(!g_allocated_pages.empty());

    auto pages = g_allocated_pages;
    for (const auto &ptr : pages) {
        free_page(ptr);
    }

    g_allocated_pages.clear();
}

TEST_CASE("operators: unlimited are not equal")
{
    {
        object_allocator<uint64_t> pool1{};
        object_allocator<uint64_t> pool2{};

        CHECK(pool1 != pool2);
        CHECK(!(pool1 == pool2));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("operators: limited are not equal")
{
    {
        object_allocator<uint64_t, 1> pool1{};
        object_allocator<uint64_t, 1> pool2{};

        CHECK(pool1 != pool2);
        CHECK(!(pool1 == pool2));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("operators: move unlimited")
{
    {
        object_allocator<uint64_t> pool1{};
        object_allocator<uint64_t> pool2{};

        pool1 = std::move(pool2);

        CHECK(pool1.page_stack_size() == 0);
        CHECK(pool1.objt_stack_size() == 0);
        CHECK(pool1.num_page() == 0);
        CHECK(pool1.num_free() == 0);
        CHECK(pool1.num_used() == 0);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("operators: move unlimited with allocations")
{
    {
        object_allocator<uint64_t> pool1{};
        object_allocator<uint64_t> pool2{};

        pool1.allocate(1);
        pool1 = std::move(pool2);

        CHECK(pool1.page_stack_size() == 0);
        CHECK(pool1.objt_stack_size() == 0);
        CHECK(pool1.num_page() == 0);
        CHECK(pool1.num_free() == 0);
        CHECK(pool1.num_used() == 0);
    }

    CHECK(!g_allocated_pages.empty());

    auto pages = g_allocated_pages;
    for (const auto &ptr : pages) {
        free_page(ptr);
    }

    g_allocated_pages.clear();
}

TEST_CASE("operators: move limited")
{
    {
        object_allocator<uint64_t, 1> pool1{};
        object_allocator<uint64_t, 1> pool2{};

        pool1 = std::move(pool2);

        CHECK(pool1.page_stack_size() == 1);
        CHECK(pool1.objt_stack_size() == 3);
        CHECK(pool1.num_page() == 1);
        CHECK(pool1.num_free() == blocks_per_page);
        CHECK(pool1.num_used() == 0);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("allocate: contains")
{
    {
        uint64_t test;
        object_allocator<uint64_t> pool{};

        auto ptr1 = pool.allocate(1);
        auto ptr2 = pool.allocate(1);
        auto ptr3 = pool.allocate(1);
        auto ptr4 = pool.allocate(1);

        CHECK(pool.contains(ptr1));
        CHECK(pool.contains(ptr2));
        CHECK(pool.contains(ptr3));
        CHECK(pool.contains(ptr4));

        CHECK(!pool.contains(&test));

        pool.deallocate(ptr1, 1);
        pool.deallocate(ptr2, 1);
        pool.deallocate(ptr3, 1);
        pool.deallocate(ptr4, 1);
    }

    CHECK(g_allocated_pages.empty());
}

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

#include <bfbenchmark.h>

constexpr const auto NUM_ITERATIONS = 0x100U;

TEST_CASE("base line")
{
    bfdebug_lnbr(0);
    bfdebug_info(0, "base line");
    bfdebug_brk2(0);
    {
        clear_memory_stats();
        std::queue<uint64_t, std::list<uint64_t>> d;

        auto results1 = benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            { d.push(i); }
        });

        auto results2 = benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            { d.pop(); }
        });

        auto results3 = benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            { d.push(i); }
        });

        print_memory_stats();
        clear_memory_stats();

        bfdebug_ndec(0, "push #1", results1);
        bfdebug_ndec(0, "pop #1", results2);
        bfdebug_ndec(0, "push #2", results3);
    }
}

TEST_CASE("unlimited queue")
{
    bfdebug_lnbr(0);
    bfdebug_info(0, "unlimited queue");
    bfdebug_brk2(0);
    {
        clear_memory_stats();
        std::queue<uint64_t, std::list<uint64_t, object_allocator<uint64_t>>> d;

        auto results1 = benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            { d.push(i); }
        });

        auto results2 = benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            { d.pop(); }
        });

        auto results3 = benchmark([&] {
            for (auto i = 0U; i < NUM_ITERATIONS; i++)
            { d.push(i); }
        });

        print_memory_stats();
        clear_memory_stats();

        bfdebug_ndec(0, "push #1", results1);
        bfdebug_ndec(0, "pop #1", results2);
        bfdebug_ndec(0, "push #2", results3);
    }
}

TEST_CASE("limited queue")
{
    bfdebug_lnbr(0);
    bfdebug_info(0, "limited queue");
    bfdebug_brk2(0);
    {
        struct list_element {
            uint64_t data;
            uint64_t next;
            uint64_t prev;
        };

#ifndef _MSC_VER
        constexpr const auto num = 0x1000 / sizeof(list_element);
#else
        constexpr const auto num = 0x1000 / sizeof(list_element) - 1;
#endif

        std::queue<uint64_t, std::list<uint64_t, object_allocator<uint64_t, 1>>> d;

        bfdebug_ndec(0, "push #1", benchmark([&] {
            for (auto i = 0U; i < num; i++)
            { d.push(i); }
        }));
        CHECK_THROWS(d.push(42));

        bfdebug_ndec(0, "pop #1", benchmark([&] {
            for (auto i = 0U; i < num; i++)
            { d.pop(); }
        }));

        bfdebug_ndec(0, "push #2", benchmark([&] {
            for (auto i = 0U; i < num; i++)
            { d.push(i); }
        }));
        CHECK_THROWS(d.push(42));
    }
}
