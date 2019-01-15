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
