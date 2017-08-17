//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
// Author: Connor Davis      <davisc@ainfosec.com>
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
#include <intrinsics/x86/intel_x64.h>
#include <intrinsics/x86/common_x64.h>
#include <test/vmcs_utils.h>

#ifdef _HIPPOMOCKS__ENABLE_CFUNC_MOCKING_SUPPORT

using namespace intel_x64;

std::map<uint32_t, uint64_t> g_msrs;
std::map<uint64_t, uint64_t> g_vmcs_fields;

static bool
test_vmread(uint64_t field, uint64_t *val) noexcept
{
    *val = g_vmcs_fields[field];
    return true;
}

static bool
test_vmwrite(uint64_t field, uint64_t val) noexcept
{
    g_vmcs_fields[field] = val;
    return true;
}

static void
setup_intrinsics(MockRepository &mocks)
{
    mocks.OnCallFunc(_vmread).Do(test_vmread);
    mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
}

TEST_CASE("test name goes here")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(true);
}

TEST_CASE("vmcs_host_es_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_es_selector::set(100UL);

    CHECK(vmcs::host_es_selector::get() == 100UL);
    CHECK(vmcs::host_es_selector::exists());

    vmcs::host_es_selector::set_if_exists(200UL);

    CHECK(vmcs::host_es_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_host_es_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_es_selector::rpl::set(1UL);
    CHECK(vmcs::host_es_selector::rpl::get() == 1UL);

    vmcs::host_es_selector::rpl::set(0UL);
    CHECK(vmcs::host_es_selector::rpl::get() == 0UL);

    vmcs::host_es_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::host_es_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_es_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::host_es_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_es_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_es_selector::ti::set(true);
    CHECK(vmcs::host_es_selector::ti::get());

    vmcs::host_es_selector::ti::set(false);
    CHECK_FALSE(vmcs::host_es_selector::ti::get());

    vmcs::host_es_selector::ti::set_if_exists(true);
    CHECK(vmcs::host_es_selector::ti::get_if_exists());

    vmcs::host_es_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::host_es_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_host_es_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_es_selector::index::set(1UL);
    CHECK(vmcs::host_es_selector::index::get() == 1UL);

    vmcs::host_es_selector::index::set(0UL);
    CHECK(vmcs::host_es_selector::index::get() == 0UL);

    vmcs::host_es_selector::index::set_if_exists(1UL);
    CHECK(vmcs::host_es_selector::index::get_if_exists() == 1UL);

    vmcs::host_es_selector::index::set_if_exists(0UL);
    CHECK(vmcs::host_es_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_cs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cs_selector::set(gsl::narrow_cast<uint32_t>(100UL));

    CHECK(vmcs::host_cs_selector::get() == 100UL);
    CHECK(vmcs::host_cs_selector::exists());

    vmcs::host_cs_selector::set_if_exists(200UL);

    CHECK(vmcs::host_cs_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_host_cs_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cs_selector::rpl::set(1UL);
    CHECK(vmcs::host_cs_selector::rpl::get() == 1UL);

    vmcs::host_cs_selector::rpl::set(0UL);
    CHECK(vmcs::host_cs_selector::rpl::get() == 0UL);

    vmcs::host_cs_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::host_cs_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_cs_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::host_cs_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_cs_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cs_selector::ti::set(true);
    CHECK(vmcs::host_cs_selector::ti::get());

    vmcs::host_cs_selector::ti::set(false);
    CHECK_FALSE(vmcs::host_cs_selector::ti::get());

    vmcs::host_cs_selector::ti::set_if_exists(true);
    CHECK(vmcs::host_cs_selector::ti::get_if_exists());

    vmcs::host_cs_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::host_cs_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_host_cs_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_cs_selector::index::set(1UL);
    CHECK(vmcs::host_cs_selector::index::get() == 1UL);

    vmcs::host_cs_selector::index::set(0UL);
    CHECK(vmcs::host_cs_selector::index::get() == 0UL);

    vmcs::host_cs_selector::index::set_if_exists(1UL);
    CHECK(vmcs::host_cs_selector::index::get_if_exists() == 1UL);

    vmcs::host_cs_selector::index::set_if_exists(0UL);
    CHECK(vmcs::host_cs_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ss_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_ss_selector::set(100UL);

    CHECK(vmcs::host_ss_selector::get() == 100UL);
    CHECK(vmcs::host_ss_selector::exists());

    vmcs::host_ss_selector::set_if_exists(200UL);

    CHECK(vmcs::host_ss_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_host_ss_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_ss_selector::rpl::set(1UL);
    CHECK(vmcs::host_ss_selector::rpl::get() == 1UL);

    vmcs::host_ss_selector::rpl::set(0UL);
    CHECK(vmcs::host_ss_selector::rpl::get() == 0UL);

    vmcs::host_ss_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::host_ss_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_ss_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::host_ss_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ss_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_ss_selector::ti::set(true);
    CHECK(vmcs::host_ss_selector::ti::get());

    vmcs::host_ss_selector::ti::set(false);
    CHECK_FALSE(vmcs::host_ss_selector::ti::get());

    vmcs::host_ss_selector::ti::set_if_exists(true);
    CHECK(vmcs::host_ss_selector::ti::get_if_exists());

    vmcs::host_ss_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::host_ss_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_host_ss_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_ss_selector::index::set(1UL);
    CHECK(vmcs::host_ss_selector::index::get() == 1UL);

    vmcs::host_ss_selector::index::set(0UL);
    CHECK(vmcs::host_ss_selector::index::get() == 0UL);

    vmcs::host_ss_selector::index::set_if_exists(1UL);
    CHECK(vmcs::host_ss_selector::index::get_if_exists() == 1UL);

    vmcs::host_ss_selector::index::set_if_exists(0UL);
    CHECK(vmcs::host_ss_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ds_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_ds_selector::set(100UL);

    CHECK(vmcs::host_ds_selector::get() == 100UL);
    CHECK(vmcs::host_ds_selector::exists());

    vmcs::host_ds_selector::set_if_exists(200UL);

    CHECK(vmcs::host_ds_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_host_ds_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_ds_selector::rpl::set(1UL);
    CHECK(vmcs::host_ds_selector::rpl::get() == 1UL);

    vmcs::host_ds_selector::rpl::set(0UL);
    CHECK(vmcs::host_ds_selector::rpl::get() == 0UL);

    vmcs::host_ds_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::host_ds_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_ds_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::host_ds_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_ds_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_ds_selector::ti::set(true);
    CHECK(vmcs::host_ds_selector::ti::get());

    vmcs::host_ds_selector::ti::set(false);
    CHECK_FALSE(vmcs::host_ds_selector::ti::get());

    vmcs::host_ds_selector::ti::set_if_exists(true);
    CHECK(vmcs::host_ds_selector::ti::get_if_exists());

    vmcs::host_ds_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::host_ds_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_host_ds_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_ds_selector::index::set(1UL);
    CHECK(vmcs::host_ds_selector::index::get() == 1UL);

    vmcs::host_ds_selector::index::set(0UL);
    CHECK(vmcs::host_ds_selector::index::get() == 0UL);

    vmcs::host_ds_selector::index::set_if_exists(1UL);
    CHECK(vmcs::host_ds_selector::index::get_if_exists() == 1UL);

    vmcs::host_ds_selector::index::set_if_exists(0UL);
    CHECK(vmcs::host_ds_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_fs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_fs_selector::set(100UL);

    CHECK(vmcs::host_fs_selector::get() == 100UL);
    CHECK(vmcs::host_fs_selector::exists());

    vmcs::host_fs_selector::set_if_exists(200UL);

    CHECK(vmcs::host_fs_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_host_fs_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_fs_selector::rpl::set(1UL);
    CHECK(vmcs::host_fs_selector::rpl::get() == 1UL);

    vmcs::host_fs_selector::rpl::set(0UL);
    CHECK(vmcs::host_fs_selector::rpl::get() == 0UL);

    vmcs::host_fs_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::host_fs_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_fs_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::host_fs_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_fs_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_fs_selector::ti::set(true);
    CHECK(vmcs::host_fs_selector::ti::get());

    vmcs::host_fs_selector::ti::set(false);
    CHECK_FALSE(vmcs::host_fs_selector::ti::get());

    vmcs::host_fs_selector::ti::set_if_exists(true);
    CHECK(vmcs::host_fs_selector::ti::get_if_exists());

    vmcs::host_fs_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::host_fs_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_host_fs_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_fs_selector::index::set(1UL);
    CHECK(vmcs::host_fs_selector::index::get() == 1UL);

    vmcs::host_fs_selector::index::set(0UL);
    CHECK(vmcs::host_fs_selector::index::get() == 0UL);

    vmcs::host_fs_selector::index::set_if_exists(1UL);
    CHECK(vmcs::host_fs_selector::index::get_if_exists() == 1UL);

    vmcs::host_fs_selector::index::set_if_exists(0UL);
    CHECK(vmcs::host_fs_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_gs_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_gs_selector::set(100UL);

    CHECK(vmcs::host_gs_selector::get() == 100UL);
    CHECK(vmcs::host_gs_selector::exists());

    vmcs::host_gs_selector::set_if_exists(200UL);

    CHECK(vmcs::host_gs_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_host_gs_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_gs_selector::rpl::set(1UL);
    CHECK(vmcs::host_gs_selector::rpl::get() == 1UL);

    vmcs::host_gs_selector::rpl::set(0UL);
    CHECK(vmcs::host_gs_selector::rpl::get() == 0UL);

    vmcs::host_gs_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::host_gs_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_gs_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::host_gs_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_gs_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_gs_selector::ti::set(true);
    CHECK(vmcs::host_gs_selector::ti::get());

    vmcs::host_gs_selector::ti::set(false);
    CHECK_FALSE(vmcs::host_gs_selector::ti::get());

    vmcs::host_gs_selector::ti::set_if_exists(true);
    CHECK(vmcs::host_gs_selector::ti::get_if_exists());

    vmcs::host_gs_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::host_gs_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_host_gs_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_gs_selector::index::set(1UL);
    CHECK(vmcs::host_gs_selector::index::get() == 1UL);

    vmcs::host_gs_selector::index::set(0UL);
    CHECK(vmcs::host_gs_selector::index::get() == 0UL);

    vmcs::host_gs_selector::index::set_if_exists(1UL);
    CHECK(vmcs::host_gs_selector::index::get_if_exists() == 1UL);

    vmcs::host_gs_selector::index::set_if_exists(0UL);
    CHECK(vmcs::host_gs_selector::index::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_tr_selector")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_tr_selector::set(gsl::narrow_cast<uint32_t>(100UL));

    CHECK(vmcs::host_tr_selector::get() == 100UL);
    CHECK(vmcs::host_tr_selector::exists());

    vmcs::host_tr_selector::set_if_exists(200UL);

    CHECK(vmcs::host_tr_selector::get_if_exists() == 200UL);
}

TEST_CASE("vmcs_host_tr_selector_rpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_tr_selector::rpl::set(1UL);
    CHECK(vmcs::host_tr_selector::rpl::get() == 1UL);

    vmcs::host_tr_selector::rpl::set(0UL);
    CHECK(vmcs::host_tr_selector::rpl::get() == 0UL);

    vmcs::host_tr_selector::rpl::set_if_exists(1UL);
    CHECK(vmcs::host_tr_selector::rpl::get_if_exists() == 1UL);

    vmcs::host_tr_selector::rpl::set_if_exists(0UL);
    CHECK(vmcs::host_tr_selector::rpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_host_tr_selector_ti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_tr_selector::ti::set(true);
    CHECK(vmcs::host_tr_selector::ti::get());

    vmcs::host_tr_selector::ti::set(false);
    CHECK_FALSE(vmcs::host_tr_selector::ti::get());

    vmcs::host_tr_selector::ti::set_if_exists(true);
    CHECK(vmcs::host_tr_selector::ti::get_if_exists());

    vmcs::host_tr_selector::ti::set_if_exists(false);
    CHECK_FALSE(vmcs::host_tr_selector::ti::get_if_exists());
}

TEST_CASE("vmcs_host_tr_selector_index")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::host_tr_selector::index::set(1UL);
    CHECK(vmcs::host_tr_selector::index::get() == 1UL);

    vmcs::host_tr_selector::index::set(0UL);
    CHECK(vmcs::host_tr_selector::index::get() == 0UL);

    vmcs::host_tr_selector::index::set_if_exists(1UL);
    CHECK(vmcs::host_tr_selector::index::get_if_exists() == 1UL);

    vmcs::host_tr_selector::index::set_if_exists(0UL);
    CHECK(vmcs::host_tr_selector::index::get_if_exists() == 0UL);
}

#endif
