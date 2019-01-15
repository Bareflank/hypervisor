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

#include <bfgsl.h>
#include <debug/debug_ring/debug_ring.h>

using namespace bfvmm;

debug_ring_resources_t *drr;

char rb[DEBUG_RING_SIZE];
char wb[DEBUG_RING_SIZE + 100];

void
init_wb(uint64_t num, char val = 'A')
{
    for (auto i = 0U; i < num; i++) {
        gsl::at(wb, static_cast<std::ptrdiff_t>(i)) = val;
    }

    gsl::at(wb, static_cast<std::ptrdiff_t>(num)) = 0;
}

TEST_CASE("get_drr: get_drr_invalid_drr")
{
    CHECK(get_drr(0, nullptr) == GET_DRR_FAILURE);
}

TEST_CASE("get_drr: get_drr_invalid_vcpuid")
{
    CHECK(get_drr(0x1000, &drr) == GET_DRR_FAILURE);
}

TEST_CASE("debug_ring: write_out_of_memory")
{
    debug_ring dr(0);

    CHECK_NOTHROW(dr.write("hello"));
}

TEST_CASE("debug_ring_read: read_with_invalid_drr")
{
    CHECK(debug_ring_read(nullptr, static_cast<char *>(rb), DEBUG_RING_SIZE) == 0);
}

TEST_CASE("debug_ring_read: read_with_null_string")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    CHECK(debug_ring_read(drr, nullptr, DEBUG_RING_SIZE) == 0);
}

TEST_CASE("debug_ring_read: read_with_zero_length")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    CHECK(debug_ring_read(drr, static_cast<char *>(rb), 0) == 0);
}

TEST_CASE("write: write_with_zero_length")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    auto zero_len_wb = "";

    CHECK_NOTHROW(dr.write(static_cast<const char *>(zero_len_wb)));
}

TEST_CASE("write: write_string_to_dr_that_is_larger_than_dr")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    init_wb(DEBUG_RING_SIZE);

    CHECK_NOTHROW(dr.write(static_cast<const char *>(wb)));
}

TEST_CASE("write: write_string_to_dr_that_is_much_larger_than_dr")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    init_wb(DEBUG_RING_SIZE + 50);

    CHECK_NOTHROW(dr.write(static_cast<const char *>(wb)));
}

TEST_CASE("write: write_one_small_string_to_dr")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    auto small_wb = "01234";

    CHECK_NOTHROW(dr.write(static_cast<const char *>(small_wb)));
    CHECK(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == 5);
}

TEST_CASE("write: fill_dr")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    init_wb(DEBUG_RING_SIZE - 1);

    CHECK_NOTHROW(dr.write(static_cast<const char *>(wb)));
    CHECK(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == DEBUG_RING_SIZE - 1);
    CHECK(rb[DEBUG_RING_SIZE - 1] == '\0');
}

TEST_CASE("write: overcommit_dr")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    init_wb(DEBUG_RING_SIZE - 10, 'A');
    CHECK_NOTHROW(dr.write(static_cast<const char *>(wb)));

    init_wb(100, 'B');
    CHECK_NOTHROW(dr.write(static_cast<const char *>(wb)));

    CHECK(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == 100);
    CHECK(rb[0] == 'B');
}

TEST_CASE("write: overcommit_dr_more_than_once")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    init_wb(DEBUG_RING_SIZE - 150, 'A');
    CHECK_NOTHROW(dr.write(static_cast<const char *>(wb)));

    init_wb(DEBUG_RING_SIZE - 150, 'B');
    CHECK_NOTHROW(dr.write(static_cast<const char *>(wb)));

    init_wb(DEBUG_RING_SIZE - 150, 'C');
    CHECK_NOTHROW(dr.write(static_cast<const char *>(wb)));

    CHECK(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == DEBUG_RING_SIZE - 150);
    CHECK(rb[0] == 'C');
}

TEST_CASE("debug_ring_read: read_with_empty_dr")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    CHECK(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == 0);
}

TEST_CASE("write: acceptance_test_stress")
{
    debug_ring dr(0);
    get_drr(0, &drr);

    auto small_wb = "012";

    for (auto i = 0U; i < DEBUG_RING_SIZE; i++) {
        dr.write(static_cast<const char *>(small_wb));
    }

    // The total number of bytes that we read out, should be equal to
    // the total number of strings that can fit into the debug ring, minus
    // the '\0' for each string (as they are stripped).

    auto num = DEBUG_RING_SIZE / (strlen(static_cast<const char *>(small_wb)) + 1);
    auto total = num * strlen(static_cast<const char *>(small_wb));

    CHECK(debug_ring_read(drr, static_cast<char *>(rb), DEBUG_RING_SIZE) == total);
    CHECK(rb[0] == '0');
}
