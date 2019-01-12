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
    object_allocator pool{0, 0};
}

TEST_CASE("basic allocator size")
{
    object_allocator pool{sizeof(uint64_t), 0};
    CHECK(pool.size(nullptr) == sizeof(uint64_t));
}

TEST_CASE("construction: limited")
{
    {
        object_allocator pool{sizeof(uint64_t), 1};

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
        object_allocator pool1{sizeof(uint64_t), 1};
        object_allocator pool2{sizeof(uint64_t), 0};

        CHECK_THROWS(pool2.allocate());
    }
}

TEST_CASE("construction: unlimited")
{
    {
        object_allocator pool{sizeof(uint64_t)};

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
        object_allocator pool{sizeof(uint64_t)};

        auto ptr = pool.allocate();
        CHECK_NOTHROW(ptr);

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page - 1);
        CHECK(pool.num_used() == 1);

        pool.deallocate(ptr);
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("allocate: single allocation without free")
{
    {
        object_allocator pool{sizeof(uint64_t)};

        CHECK_NOTHROW(pool.allocate());

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

TEST_CASE("allocate: multiple allocations")
{
    {
        object_allocator pool{sizeof(uint64_t)};

        for (auto i = 0; i < blocks_per_page * 4; i++) {
            pool.allocate();
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

        object_allocator pool{sizeof(test)};

        for (auto i = 0U; i < 0x1000U / sizeof(test); i++) {
            CHECK_NOTHROW(pool.allocate());
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 1);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == 0x1000U / sizeof(test));

        CHECK_NOTHROW(pool.allocate());

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
        object_allocator pool{sizeof(uint64_t), 1};

        for (auto i = 0; i < blocks_per_page; i++) {
            pool.allocate();
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == blocks_per_page);

        CHECK_THROWS(pool.allocate());
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
        object_allocator pool{sizeof(uint64_t)};

        CHECK_NOTHROW(pool.deallocate(&nothing));
    }

    CHECK(g_allocated_pages.empty());
}

TEST_CASE("deallocate: deallocate single allocation")
{
    {
        object_allocator pool{sizeof(uint64_t)};

        auto alloc = pool.allocate();

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 3);
        CHECK(pool.num_page() == 1);
        CHECK(pool.num_free() == blocks_per_page - 1);
        CHECK(pool.num_used() == 1);

        CHECK_NOTHROW(pool.deallocate(alloc));

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
        std::list<void *> v{};
        object_allocator pool{sizeof(uint64_t)};

        for (auto i = 0; i < blocks_per_page * 4; i++) {
            v.push_back(pool.allocate());
        }

        CHECK(pool.page_stack_size() == 1);
        CHECK(pool.objt_stack_size() == 9);
        CHECK(pool.num_page() == 4);
        CHECK(pool.num_free() == 0);
        CHECK(pool.num_used() == blocks_per_page * 4);

        for (auto elem : v) {
            pool.deallocate(elem);
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
        object_allocator pool{sizeof(__oa_page)};

        CHECK_NOTHROW(pool.allocate());

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
        object_allocator pool{sizeof(__oa_page)};

        CHECK_NOTHROW(pool.allocate());
        CHECK_NOTHROW(pool.allocate());
        CHECK_NOTHROW(pool.allocate());

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

TEST_CASE("allocate: contains")
{
    {
        uint64_t test;
        object_allocator pool{sizeof(uint64_t)};

        auto ptr1 = pool.allocate();
        auto ptr2 = pool.allocate();
        auto ptr3 = pool.allocate();
        auto ptr4 = pool.allocate();

        CHECK(pool.contains(ptr1));
        CHECK(pool.contains(ptr2));
        CHECK(pool.contains(ptr3));
        CHECK(pool.contains(ptr4));

        CHECK(!pool.contains(&test));

        pool.deallocate(ptr1);
        pool.deallocate(ptr2);
        pool.deallocate(ptr3);
        pool.deallocate(ptr4);
    }

    CHECK(g_allocated_pages.empty());
}
