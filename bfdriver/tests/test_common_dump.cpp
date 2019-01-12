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

#include <bfdriverinterface.h>
#include <bfdebugringinterface.h>

#include <common.h>
#include <test_support.h>

debug_ring_resources_t *g_drr;

TEST_CASE("common_add_module: invalid drr")
{
    CHECK(common_dump_vmm(nullptr, 0) == BF_ERROR_INVALID_ARG);
}

TEST_CASE("common_add_module: unloaded")
{
    CHECK(common_dump_vmm(&g_drr, 0) == BF_ERROR_VMM_INVALID_STATE);
}

TEST_CASE("common_add_module: get drr fails")
{
    binaries_info info{&g_file, g_filenames_get_drr_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_dump_vmm(&g_drr, 0) == ENTRY_ERROR_UNKNOWN);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_add_module: success")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_dump_vmm(&g_drr, 0) == BF_SUCCESS);
    CHECK(common_fini() == BF_SUCCESS);
}
