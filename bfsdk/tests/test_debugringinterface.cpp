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
