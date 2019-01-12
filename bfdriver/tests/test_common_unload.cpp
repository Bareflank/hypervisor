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
#include <hippomocks.h>

#include <bfdriverinterface.h>

#include <common.h>
#include <test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("common_unload_vmm: success")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_stop_vmm() == BF_SUCCESS);
    CHECK(common_unload_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_unload_vmm: already unloaded")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_unload_vmm() == BF_SUCCESS);
    CHECK(common_unload_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_unload_vmm: loaded")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_unload_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_unload_vmm: running")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_unload_vmm() == BF_ERROR_VMM_INVALID_STATE);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_unload_vmm: corrupt")
{
    binaries_info info{&g_file, g_filenames_vmm_fini_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_ERROR_VMM_CORRUPTED);
    CHECK(common_unload_vmm() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

TEST_CASE("common_start_vmm: unload fails")
{
    binaries_info info{&g_file, g_filenames_fini_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_stop_vmm() == BF_SUCCESS);
    CHECK(common_unload_vmm() == ENTRY_ERROR_UNKNOWN);
    CHECK(common_fini() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

#endif
