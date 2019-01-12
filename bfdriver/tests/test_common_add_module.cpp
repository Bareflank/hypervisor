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

#include <common.h>
#include <test_support.h>

TEST_CASE("common_add_module: invalid file")
{
    CHECK(common_add_module(nullptr, 42) == BF_ERROR_INVALID_ARG);
}

TEST_CASE("common_add_module: invalid size")
{
    binaries_info info{&g_file, g_filenames_success, false};
    CHECK(common_add_module(info.back().file, 0) == BF_ERROR_INVALID_ARG);
}

TEST_CASE("common_add_module: success")
{
    binaries_info info{&g_file, g_filenames_success, false};
    CHECK(common_add_module(info.back().file, info.back().file_size) == BF_SUCCESS);

    REQUIRE(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_add_module: already loaded")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_add_module(info.front().file, info.front().file_size) == BF_ERROR_VMM_INVALID_STATE); \
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_add_module: already running")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_add_module(info.front().file, info.front().file_size) == BF_ERROR_VMM_INVALID_STATE);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_add_module: corrupt")
{
    binaries_info info{&g_file, g_filenames_vmm_fini_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_ERROR_VMM_CORRUPTED);
    CHECK(common_add_module(info.front().file, info.front().file_size) == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

TEST_CASE("common_add_module: too many modules")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (auto i = 0; i < MAX_NUM_MODULES; i++) {
        CHECK(common_add_module(info.back().file, info.back().file_size) == BF_SUCCESS);
    }

    CHECK(common_add_module(info.front().file, info.front().file_size) == BF_ERROR_MAX_MODULES_REACHED);
    REQUIRE(common_fini() == BF_SUCCESS);
}
