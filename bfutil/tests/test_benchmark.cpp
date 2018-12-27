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
#include <bfbenchmark.h>

TEST_CASE("benchmark")
{
    CHECK(benchmark([] {
        std::cout << "the answer is 42\n";
    }) != 0);
}

TEST_CASE("non-array new/delete")
{
    [[maybe_unused]] auto dontcare0 = std::make_unique<char>();
    [[maybe_unused]] auto dontcare1 = std::unique_ptr<char>(new (std::nothrow) char);
}

TEST_CASE("array new/delete")
{
    clear_memory_stats();

    [[maybe_unused]] auto dontcare0 = std::make_unique<char[]>(42);
    [[maybe_unused]] auto dontcare1 = std::make_unique<char[]>(0x1000);
    [[maybe_unused]] auto dontcare2 = std::unique_ptr<char[]>(new (std::nothrow) char[0x1000]);

    auto page_allocs = g_page_allocs;
    auto nonpage_allocs = g_nonpage_allocs;

    CHECK(page_allocs == 0x2000);
    CHECK(nonpage_allocs == 42);
}

TEST_CASE("memory stats")
{
    print_memory_stats();
    clear_memory_stats();
}
