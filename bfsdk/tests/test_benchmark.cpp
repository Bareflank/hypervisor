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
