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

#include <map>
#include <list>
#include <queue>
#include <memory>

#include <bfgsl.h>
#include <bfbenchmark.h>
#include <memory_manager/object_allocator.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

constexpr const auto blocks_per_page = 512;
std::map<memory_manager_x64::pointer, std::unique_ptr<gsl::byte[]>> g_allocated_memory;

memory_manager_x64::pointer
test_alloc(memory_manager_x64::size_type size) noexcept
{
    memory_manager_x64::pointer ptr = nullptr;

    guard_exceptions([&]() {
        expects(size == 0x1000);

        auto mem = std::make_unique<gsl::byte[]>(size);
        ptr = mem.get();

        g_allocated_memory[ptr] = std::move(mem);
    });

    return ptr;
}

void
test_free(memory_manager_x64::pointer ptr) noexcept
{
    g_allocated_memory.erase(ptr);
}

// memory_manager_x64::pointer
// test_alloc(memory_manager_x64::size_type size) noexcept
// { return new gsl::byte[size]; }

// void
// test_free(memory_manager_x64::pointer ptr) noexcept
// { delete[](static_cast<gsl::byte *>(ptr)); }

static auto
setup_mm(MockRepository &mocks)
{
    auto mm = mocks.Mock<memory_manager_x64>();
    mocks.OnCallFunc(memory_manager_x64::instance).Return(mm);
    mocks.OnCall(mm, memory_manager_x64::alloc).Do(test_alloc);
    mocks.OnCall(mm, memory_manager_x64::free).Do(test_free);

    return mm;
}

TEST_CASE("basic allocator of 0 size")
{
    basic_object_allocator pool{0, 0};
}

TEST_CASE("construction: limited")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t, 1> pool{};

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page);
        CHECK(pool.num_used() == 0);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("construction: limited out of memory")
{
    MockRepository mocks;
    auto mm = setup_mm(mocks);

    mocks.OnCall(mm, memory_manager_x64::alloc).Return(nullptr);

    {
        object_allocator<uint64_t, 1> pool1{};
        object_allocator<uint64_t, 0> pool2{};

        CHECK_THROWS(pool2.allocate(1));
    }
}

TEST_CASE("construction: unlimited")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t> pool{};

        CHECK(pool.page_stack_size() == 0);
        CHECK(pool.objt_stack_size() == 0);
        CHECK(pool.num_page() == 0);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 0);
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("allocate: single allocation")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("allocate: single allocation without free")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t> pool{};

        CHECK_NOTHROW(pool.allocate(1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page - 1);
        CHECK(pool.num_used() == 1);
    }

    CHECK(!g_allocated_memory.empty());
    g_allocated_memory.clear();
}

TEST_CASE("allocate: single allocation n != 1")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("allocate: multiple allocations")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(!g_allocated_memory.empty());
    g_allocated_memory.clear();
}

TEST_CASE("allocate: multiple allocations with odd sized T")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(!g_allocated_memory.empty());
    g_allocated_memory.clear();
}

TEST_CASE("allocate: over limit")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(!g_allocated_memory.empty());
    g_allocated_memory.clear();
}

TEST_CASE("deallocate: deallocate without allocate")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        uint64_t nothing = 0;
        object_allocator<uint64_t> pool{};

        CHECK_NOTHROW(pool.deallocate(&nothing, 1));
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("deallocate: deallocate single allocation")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("deallocate: deallocate multiple allocations")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("max_size: can allocate max_size")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<__oa_page> pool{};

        CHECK_NOTHROW(pool.allocate(1));

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 1);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 1);
    }

    CHECK(!g_allocated_memory.empty());
    g_allocated_memory.clear();
}

TEST_CASE("max_size: can allocate max_size more than once")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(!g_allocated_memory.empty());
    g_allocated_memory.clear();
}

TEST_CASE("operators: unlimited are not equal")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t> pool1{};
        object_allocator<uint64_t> pool2{};

        CHECK(pool1 != pool2);
        CHECK(!(pool1 == pool2));
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("operators: limited are not equal")
{
    MockRepository mocks;
    setup_mm(mocks);

    {
        object_allocator<uint64_t, 1> pool1{};
        object_allocator<uint64_t, 1> pool2{};

        CHECK(pool1 != pool2);
        CHECK(!(pool1 == pool2));
    }

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("operators: move unlimited")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(g_allocated_memory.empty());
}

TEST_CASE("operators: move unlimited with allocations")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(!g_allocated_memory.empty());
    g_allocated_memory.clear();
}

TEST_CASE("operators: move limited")
{
    MockRepository mocks;
    setup_mm(mocks);

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

    CHECK(g_allocated_memory.empty());
}

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
    MockRepository mocks;
    setup_mm(mocks);

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
    MockRepository mocks;
    setup_mm(mocks);

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

#endif
