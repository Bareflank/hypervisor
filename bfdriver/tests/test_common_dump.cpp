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
