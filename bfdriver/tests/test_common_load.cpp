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
#include <hippomocks.h>

#include <bfdriverinterface.h>

#include <common.h>
#include <test_support.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

extern "C" int64_t private_setup_rsdp(void);
extern "C" int64_t private_add_modules_mdl(void);

TEST_CASE("common_load_vmm: success")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: already loaded")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: already running")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_load_vmm() == BF_ERROR_VMM_INVALID_STATE);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: corrupt")
{
    binaries_info info{&g_file, g_filenames_vmm_fini_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BF_SUCCESS);
    CHECK(common_start_vmm() == BF_SUCCESS);
    CHECK(common_fini() == BF_ERROR_VMM_CORRUPTED);
    CHECK(common_load_vmm() == BF_ERROR_VMM_CORRUPTED);

    common_reset();
}

TEST_CASE("common_load_vmm: alloc stack fails")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    MockRepository mocks;
    mocks.ExpectCallFunc(platform_alloc_rw).Return(nullptr);

    CHECK(common_load_vmm() == BF_ERROR_OUT_OF_MEMORY);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: alloc tss fails")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    MockRepository mocks;
    mocks.ExpectCallFunc(platform_alloc_rw).Do(malloc);
    mocks.ExpectCallFunc(platform_alloc_rw).Return(nullptr);

    CHECK(common_load_vmm() == BF_ERROR_OUT_OF_MEMORY);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: rsdp fails")
{
    binaries_info info{&g_file, g_filenames_success, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    MockRepository mocks;
    mocks.ExpectCallFunc(private_setup_rsdp).Return(-1);

    CHECK(common_load_vmm() == -1);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: missing symbols")
{
    auto filenames = g_filenames_success;
    filenames.pop_back();

    binaries_info info{&g_file, filenames, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == BFELF_ERROR_NO_SUCH_SYMBOL);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: no modules added")
{
    CHECK(common_load_vmm() == BF_ERROR_NO_MODULES_ADDED);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: init fails")
{
    binaries_info info{&g_file, g_filenames_init_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == ENTRY_ERROR_UNKNOWN);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: set rsdp fails")
{
    binaries_info info{&g_file, g_filenames_set_rsdp_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == ENTRY_ERROR_UNKNOWN);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: add modules mdl fails")
{
    binaries_info info{&g_file, g_filenames_add_mdl_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    CHECK(common_load_vmm() == ENTRY_ERROR_UNKNOWN);
    CHECK(common_fini() == BF_SUCCESS);
}

TEST_CASE("common_load_vmm: add tss mdl fails")
{
    binaries_info info{&g_file, g_filenames_add_mdl_fails, false};

    for (const auto &binary : info.binaries()) {
        REQUIRE(common_add_module(binary.file, binary.file_size) == BF_SUCCESS);
    }

    MockRepository mocks;
    mocks.OnCallFunc(private_add_modules_mdl).Return(BF_SUCCESS);

    CHECK(common_load_vmm() == ENTRY_ERROR_UNKNOWN);
    CHECK(common_fini() == BF_SUCCESS);
}

#endif
