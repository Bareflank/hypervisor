//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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
#include <hippomocks.h>

#include <bfdriverinterface.h>

#include <common.h>
#include <test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

TEST_CASE("common_stop_vmm: success")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_stop_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_stop_vmm: unloaded")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_stop_vmm() == BF_ERROR_VMM_INVALID_STATE);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_stop_vmm: not running")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_stop_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_stop_vmm: already stopped")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_stop_vmm() == BF_SUCCESS);
    CHECK(common_stop_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_stop_vmm: corrupt")
{
    binaries_info info{&g_file, g_filenames_vmm_fini_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_ERROR_VMM_CORRUPTED);
    CHECK(common_stop_vmm() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

TEST_CASE("common_start_vmm: stop fails")
{
    binaries_info info{&g_file, g_filenames_vmm_fini_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_stop_vmm() == ENTRY_ERROR_UNKNOWN);
    CHECK(common_fini() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

TEST_CASE("common_stop_vmm: set affinity fails")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);

    MockRepository mocks;
    mocks.OnCallFunc(platform_set_affinity).Return(BF_ERROR_UNKNOWN);

    CHECK(common_stop_vmm() == BF_ERROR_UNKNOWN);
    CHECK(common_fini() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

TEST_CASE("common_stop_vmm: vmcall fails")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);

    MockRepository mocks;
    mocks.OnCallFunc(_vmcall);

    CHECK(common_stop_vmm() == ENTRY_ERROR_VMM_STOP_FAILED);
    CHECK(common_fini() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

#endif
