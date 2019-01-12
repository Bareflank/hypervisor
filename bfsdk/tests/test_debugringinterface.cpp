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
#include <bfdebugringinterface.h>

char g_buf[DEBUG_RING_SIZE] = {};
debug_ring_resources_t g_drr{};

TEST_CASE("debug_ring_read: invalid drr")
{
    CHECK(debug_ring_read(nullptr, static_cast<char *>(g_buf), DEBUG_RING_SIZE) == 0);
}

TEST_CASE("debug_ring_read: invalid str")
{
    CHECK(debug_ring_read(&g_drr, nullptr, DEBUG_RING_SIZE) == 0);
}

TEST_CASE("debug_ring_read: invalid len")
{
    CHECK(debug_ring_read(&g_drr, static_cast<char *>(g_buf), 0) == 0);
}

TEST_CASE("debug_ring_read: invalid spos / epos")
{
    g_drr.spos = 42;
    g_drr.epos = 0;
    CHECK(debug_ring_read(&g_drr, static_cast<char *>(g_buf), DEBUG_RING_SIZE) == 0);
}

TEST_CASE("debug_ring_read: no data")
{
    g_drr.spos = 0;
    g_drr.epos = 0;
    CHECK(debug_ring_read(&g_drr, static_cast<char *>(g_buf), DEBUG_RING_SIZE) == 0);
}

TEST_CASE("debug_ring_read: content, but no read buffer")
{
    g_drr.spos = 0;
    g_drr.epos = 42;
    CHECK(debug_ring_read(&g_drr, static_cast<char *>(g_buf), 1) == 0);
}

TEST_CASE("debug_ring_read: all 0")
{
    g_drr.spos = DEBUG_RING_SIZE - 42;
    g_drr.epos = DEBUG_RING_SIZE + 42;

    auto view = gsl::make_span(g_drr.buf);
    for (auto &elem : view) {
        elem = 0;
    }

    CHECK(debug_ring_read(&g_drr, static_cast<char *>(g_buf), DEBUG_RING_SIZE) == 0);
}

TEST_CASE("debug_ring_read: wrap")
{
    g_drr.spos = DEBUG_RING_SIZE - 42;
    g_drr.epos = DEBUG_RING_SIZE + 42;

    auto view = gsl::make_span(g_drr.buf);
    for (auto &elem : view) {
        elem = 'A';
    }

    CHECK(debug_ring_read(&g_drr, static_cast<char *>(g_buf), DEBUG_RING_SIZE) == 42 * 2);
}

TEST_CASE("debug_ring_read: full")
{
    g_drr.spos = 0;
    g_drr.epos = DEBUG_RING_SIZE;

    auto view = gsl::make_span(g_drr.buf);
    for (auto &elem : view) {
        elem = 'A';
    }

    CHECK(debug_ring_read(&g_drr, static_cast<char *>(g_buf), DEBUG_RING_SIZE) == DEBUG_RING_SIZE - 1);
}
