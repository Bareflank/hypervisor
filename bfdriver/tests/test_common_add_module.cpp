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
