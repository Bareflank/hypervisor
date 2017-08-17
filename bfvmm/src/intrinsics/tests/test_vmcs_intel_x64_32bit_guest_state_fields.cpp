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

uint64_t
test_read_msr(uint32_t addr) noexcept
{ return g_msrs[addr]; }

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
    mocks.OnCallFunc(_read_msr).Do(test_read_msr);
    mocks.OnCallFunc(_vmread).Do(test_vmread);
    mocks.OnCallFunc(_vmwrite).Do(test_vmwrite);
}

TEST_CASE("test name goes here")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(true);
}

TEST_CASE("vmcs_guest_es_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_es_limit::exists());

    vmcs::guest_es_limit::set(1UL);
    CHECK(vmcs::guest_es_limit::get() == 1UL);

    vmcs::guest_es_limit::set_if_exists(1UL);
    CHECK(vmcs::guest_es_limit::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_guest_cs_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_cs_limit::exists());

    vmcs::guest_cs_limit::set(1UL);
    CHECK(vmcs::guest_cs_limit::get() == 1UL);

    vmcs::guest_cs_limit::set_if_exists(1UL);
    CHECK(vmcs::guest_cs_limit::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_guest_ss_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_ss_limit::exists());

    vmcs::guest_ss_limit::set(1UL);
    CHECK(vmcs::guest_ss_limit::get() == 1UL);

    vmcs::guest_ss_limit::set_if_exists(1UL);
    CHECK(vmcs::guest_ss_limit::get_if_exists() == 1UL);
}


TEST_CASE("vmcs_guest_ds_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_ds_limit::exists());

    vmcs::guest_ds_limit::set(1UL);
    CHECK(vmcs::guest_ds_limit::get() == 1UL);

    vmcs::guest_ds_limit::set_if_exists(1UL);
    CHECK(vmcs::guest_ds_limit::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_guest_fs_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_fs_limit::exists());

    vmcs::guest_fs_limit::set(1UL);
    CHECK(vmcs::guest_fs_limit::get() == 1UL);

    vmcs::guest_fs_limit::set_if_exists(1UL);
    CHECK(vmcs::guest_fs_limit::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_guest_gs_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_gs_limit::exists());

    vmcs::guest_gs_limit::set(1UL);
    CHECK(vmcs::guest_gs_limit::get() == 1UL);

    vmcs::guest_gs_limit::set_if_exists(1UL);
    CHECK(vmcs::guest_gs_limit::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_guest_ldtr_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_ldtr_limit::exists());

    vmcs::guest_ldtr_limit::set(1UL);
    CHECK(vmcs::guest_ldtr_limit::get() == 1UL);

    vmcs::guest_ldtr_limit::set_if_exists(1UL);
    CHECK(vmcs::guest_ldtr_limit::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_guest_tr_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_tr_limit::exists());

    vmcs::guest_tr_limit::set(1UL);
    CHECK(vmcs::guest_tr_limit::get() == 1UL);

    vmcs::guest_tr_limit::set_if_exists(1UL);
    CHECK(vmcs::guest_tr_limit::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_guest_gdtr_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_gdtr_limit::exists());

    vmcs::guest_gdtr_limit::set(1UL);
    CHECK(vmcs::guest_gdtr_limit::get() == 1UL);

    vmcs::guest_gdtr_limit::set_if_exists(1UL);
    CHECK(vmcs::guest_gdtr_limit::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_guest_idtr_limit")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_idtr_limit::exists());

    vmcs::guest_idtr_limit::set(1UL);
    CHECK(vmcs::guest_idtr_limit::get() == 1UL);

    vmcs::guest_idtr_limit::set_if_exists(1UL);
    CHECK(vmcs::guest_idtr_limit::get_if_exists() == 1UL);
}

TEST_CASE("vmcs_guest_es_access_rights")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::set(100UL);
    CHECK(vmcs::guest_es_access_rights::exists());
    CHECK(vmcs::guest_es_access_rights::get() == 100UL);

    vmcs::guest_es_access_rights::set_if_exists(2UL);
    CHECK(vmcs::guest_es_access_rights::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_guest_es_access_rights_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::type::set(1UL);
    CHECK(vmcs::guest_es_access_rights::type::get() == 1UL);

    vmcs::guest_es_access_rights::type::set_if_exists(0UL);
    CHECK(vmcs::guest_es_access_rights::type::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_es_access_rights_s")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::s::set(1UL);
    CHECK(vmcs::guest_es_access_rights::s::get() == 1UL);

    vmcs::guest_es_access_rights::s::set_if_exists(0UL);
    CHECK(vmcs::guest_es_access_rights::s::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_es_access_rights_dpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::dpl::set(1UL);
    CHECK(vmcs::guest_es_access_rights::dpl::get() == 1UL);

    vmcs::guest_es_access_rights::dpl::set_if_exists(0UL);
    CHECK(vmcs::guest_es_access_rights::dpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_es_access_rights_present")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::present::set(1UL);
    CHECK(vmcs::guest_es_access_rights::present::get() == 1UL);

    vmcs::guest_es_access_rights::present::set_if_exists(0UL);
    CHECK(vmcs::guest_es_access_rights::present::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_es_access_rights_avl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::avl::set(1UL);
    CHECK(vmcs::guest_es_access_rights::avl::get() == 1UL);

    vmcs::guest_es_access_rights::avl::set_if_exists(0UL);
    CHECK(vmcs::guest_es_access_rights::avl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_es_access_rights_l")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::l::set(1UL);
    CHECK(vmcs::guest_es_access_rights::l::get() == 1UL);

    vmcs::guest_es_access_rights::l::set_if_exists(0UL);
    CHECK(vmcs::guest_es_access_rights::l::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_es_access_rights_db")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::db::set(1UL);
    CHECK(vmcs::guest_es_access_rights::db::get() == 1UL);

    vmcs::guest_es_access_rights::db::set_if_exists(0UL);
    CHECK(vmcs::guest_es_access_rights::db::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_es_access_rights_granularity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::granularity::set(1UL);
    CHECK(vmcs::guest_es_access_rights::granularity::get() == 1UL);

    vmcs::guest_es_access_rights::granularity::set_if_exists(0UL);
    CHECK(vmcs::guest_es_access_rights::granularity::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_es_access_rights_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::reserved::set(0x10F00U);
    CHECK(vmcs::guest_es_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_es_access_rights::reserved::set_if_exists(0UL);
    CHECK(vmcs::guest_es_access_rights::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_es_access_rights_unusable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_es_access_rights::unusable::set(1UL);
    CHECK(vmcs::guest_es_access_rights::unusable::get() == 1UL);

    vmcs::guest_es_access_rights::unusable::set_if_exists(0UL);
    CHECK(vmcs::guest_es_access_rights::unusable::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_access_rights")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::set(100UL);
    CHECK(vmcs::guest_cs_access_rights::exists());
    CHECK(vmcs::guest_cs_access_rights::get() == 100UL);

    vmcs::guest_cs_access_rights::set_if_exists(2UL);
    CHECK(vmcs::guest_cs_access_rights::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_guest_cs_access_rights_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::type::set(1UL);
    CHECK(vmcs::guest_cs_access_rights::type::get() == 1UL);

    vmcs::guest_cs_access_rights::type::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_access_rights::type::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_access_rights_s")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::s::set(1UL);
    CHECK(vmcs::guest_cs_access_rights::s::get() == 1UL);

    vmcs::guest_cs_access_rights::s::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_access_rights::s::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_access_rights_dpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::dpl::set(1UL);
    CHECK(vmcs::guest_cs_access_rights::dpl::get() == 1UL);

    vmcs::guest_cs_access_rights::dpl::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_access_rights::dpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_access_rights_present")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::present::set(1UL);
    CHECK(vmcs::guest_cs_access_rights::present::get() == 1UL);

    vmcs::guest_cs_access_rights::present::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_access_rights::present::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_access_rights_avl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::avl::set(1UL);
    CHECK(vmcs::guest_cs_access_rights::avl::get() == 1UL);

    vmcs::guest_cs_access_rights::avl::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_access_rights::avl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_access_rights_l")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::l::set(1UL);
    CHECK(vmcs::guest_cs_access_rights::l::get() == 1UL);

    vmcs::guest_cs_access_rights::l::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_access_rights::l::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_access_rights_db")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::db::set(1UL);
    CHECK(vmcs::guest_cs_access_rights::db::get() == 1UL);

    vmcs::guest_cs_access_rights::db::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_access_rights::db::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_access_rights_granularity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::granularity::set(1UL);
    CHECK(vmcs::guest_cs_access_rights::granularity::get() == 1UL);

    vmcs::guest_cs_access_rights::granularity::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_access_rights::granularity::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_access_rights_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::reserved::set(0x10F00U);
    CHECK(vmcs::guest_cs_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_cs_access_rights::reserved::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_access_rights::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_cs_access_rights_unusable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_cs_access_rights::unusable::set(1UL);
    CHECK(vmcs::guest_cs_access_rights::unusable::get() == 1UL);

    vmcs::guest_cs_access_rights::unusable::set_if_exists(0UL);
    CHECK(vmcs::guest_cs_access_rights::unusable::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_access_rights")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::set(100UL);
    CHECK(vmcs::guest_ss_access_rights::exists());
    CHECK(vmcs::guest_ss_access_rights::get() == 100UL);

    vmcs::guest_ss_access_rights::set_if_exists(2UL);
    CHECK(vmcs::guest_ss_access_rights::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_guest_ss_access_rights_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::type::set(1UL);
    CHECK(vmcs::guest_ss_access_rights::type::get() == 1UL);

    vmcs::guest_ss_access_rights::type::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_access_rights::type::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_access_rights_s")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::s::set(1UL);
    CHECK(vmcs::guest_ss_access_rights::s::get() == 1UL);

    vmcs::guest_ss_access_rights::s::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_access_rights::s::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_access_rights_dpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::dpl::set(1UL);
    CHECK(vmcs::guest_ss_access_rights::dpl::get() == 1UL);

    vmcs::guest_ss_access_rights::dpl::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_access_rights::dpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_access_rights_present")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::present::set(1UL);
    CHECK(vmcs::guest_ss_access_rights::present::get() == 1UL);

    vmcs::guest_ss_access_rights::present::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_access_rights::present::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_access_rights_avl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::avl::set(1UL);
    CHECK(vmcs::guest_ss_access_rights::avl::get() == 1UL);

    vmcs::guest_ss_access_rights::avl::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_access_rights::avl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_access_rights_l")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::l::set(1UL);
    CHECK(vmcs::guest_ss_access_rights::l::get() == 1UL);

    vmcs::guest_ss_access_rights::l::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_access_rights::l::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_access_rights_db")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::db::set(1UL);
    CHECK(vmcs::guest_ss_access_rights::db::get() == 1UL);

    vmcs::guest_ss_access_rights::db::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_access_rights::db::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_access_rights_granularity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::granularity::set(1UL);
    CHECK(vmcs::guest_ss_access_rights::granularity::get() == 1UL);

    vmcs::guest_ss_access_rights::granularity::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_access_rights::granularity::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_access_rights_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::reserved::set(0x10F00U);
    CHECK(vmcs::guest_ss_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_ss_access_rights::reserved::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_access_rights::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ss_access_rights_unusable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ss_access_rights::unusable::set(1UL);
    CHECK(vmcs::guest_ss_access_rights::unusable::get() == 1UL);

    vmcs::guest_ss_access_rights::unusable::set_if_exists(0UL);
    CHECK(vmcs::guest_ss_access_rights::unusable::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_access_rights")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::set(100UL);
    CHECK(vmcs::guest_ds_access_rights::exists());
    CHECK(vmcs::guest_ds_access_rights::get() == 100UL);

    vmcs::guest_ds_access_rights::set_if_exists(2UL);
    CHECK(vmcs::guest_ds_access_rights::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_guest_ds_access_rights_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::type::set(1UL);
    CHECK(vmcs::guest_ds_access_rights::type::get() == 1UL);

    vmcs::guest_ds_access_rights::type::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_access_rights::type::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_access_rights_s")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::s::set(1UL);
    CHECK(vmcs::guest_ds_access_rights::s::get() == 1UL);

    vmcs::guest_ds_access_rights::s::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_access_rights::s::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_access_rights_dpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::dpl::set(1UL);
    CHECK(vmcs::guest_ds_access_rights::dpl::get() == 1UL);

    vmcs::guest_ds_access_rights::dpl::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_access_rights::dpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_access_rights_present")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::present::set(1UL);
    CHECK(vmcs::guest_ds_access_rights::present::get() == 1UL);

    vmcs::guest_ds_access_rights::present::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_access_rights::present::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_access_rights_avl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::avl::set(1UL);
    CHECK(vmcs::guest_ds_access_rights::avl::get() == 1UL);

    vmcs::guest_ds_access_rights::avl::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_access_rights::avl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_access_rights_l")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::l::set(1UL);
    CHECK(vmcs::guest_ds_access_rights::l::get() == 1UL);

    vmcs::guest_ds_access_rights::l::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_access_rights::l::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_access_rights_db")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::db::set(1UL);
    CHECK(vmcs::guest_ds_access_rights::db::get() == 1UL);

    vmcs::guest_ds_access_rights::db::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_access_rights::db::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_access_rights_granularity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::granularity::set(1UL);
    CHECK(vmcs::guest_ds_access_rights::granularity::get() == 1UL);

    vmcs::guest_ds_access_rights::granularity::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_access_rights::granularity::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_access_rights_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::reserved::set(0x10F00U);
    CHECK(vmcs::guest_ds_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_ds_access_rights::reserved::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_access_rights::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ds_access_rights_unusable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ds_access_rights::unusable::set(1UL);
    CHECK(vmcs::guest_ds_access_rights::unusable::get() == 1UL);

    vmcs::guest_ds_access_rights::unusable::set_if_exists(0UL);
    CHECK(vmcs::guest_ds_access_rights::unusable::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_access_rights")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::set(100UL);
    CHECK(vmcs::guest_fs_access_rights::exists());
    CHECK(vmcs::guest_fs_access_rights::get() == 100UL);

    vmcs::guest_fs_access_rights::set_if_exists(2UL);
    CHECK(vmcs::guest_fs_access_rights::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_guest_fs_access_rights_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::type::set(1UL);
    CHECK(vmcs::guest_fs_access_rights::type::get() == 1UL);

    vmcs::guest_fs_access_rights::type::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_access_rights::type::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_access_rights_s")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::s::set(1UL);
    CHECK(vmcs::guest_fs_access_rights::s::get() == 1UL);

    vmcs::guest_fs_access_rights::s::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_access_rights::s::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_access_rights_dpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::dpl::set(1UL);
    CHECK(vmcs::guest_fs_access_rights::dpl::get() == 1UL);

    vmcs::guest_fs_access_rights::dpl::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_access_rights::dpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_access_rights_present")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::present::set(1UL);
    CHECK(vmcs::guest_fs_access_rights::present::get() == 1UL);

    vmcs::guest_fs_access_rights::present::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_access_rights::present::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_access_rights_avl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::avl::set(1UL);
    CHECK(vmcs::guest_fs_access_rights::avl::get() == 1UL);

    vmcs::guest_fs_access_rights::avl::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_access_rights::avl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_access_rights_l")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::l::set(1UL);
    CHECK(vmcs::guest_fs_access_rights::l::get() == 1UL);

    vmcs::guest_fs_access_rights::l::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_access_rights::l::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_access_rights_db")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::db::set(1UL);
    CHECK(vmcs::guest_fs_access_rights::db::get() == 1UL);

    vmcs::guest_fs_access_rights::db::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_access_rights::db::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_access_rights_granularity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::granularity::set(1UL);
    CHECK(vmcs::guest_fs_access_rights::granularity::get() == 1UL);

    vmcs::guest_fs_access_rights::granularity::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_access_rights::granularity::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_access_rights_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::reserved::set(0x10F00U);
    CHECK(vmcs::guest_fs_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_fs_access_rights::reserved::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_access_rights::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_fs_access_rights_unusable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_fs_access_rights::unusable::set(1UL);
    CHECK(vmcs::guest_fs_access_rights::unusable::get() == 1UL);

    vmcs::guest_fs_access_rights::unusable::set_if_exists(0UL);
    CHECK(vmcs::guest_fs_access_rights::unusable::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_access_rights")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::set(100UL);
    CHECK(vmcs::guest_gs_access_rights::exists());
    CHECK(vmcs::guest_gs_access_rights::get() == 100UL);

    vmcs::guest_gs_access_rights::set_if_exists(2UL);
    CHECK(vmcs::guest_gs_access_rights::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_guest_gs_access_rights_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::type::set(1UL);
    CHECK(vmcs::guest_gs_access_rights::type::get() == 1UL);

    vmcs::guest_gs_access_rights::type::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_access_rights::type::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_access_rights_s")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::s::set(1UL);
    CHECK(vmcs::guest_gs_access_rights::s::get() == 1UL);

    vmcs::guest_gs_access_rights::s::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_access_rights::s::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_access_rights_dpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::dpl::set(1UL);
    CHECK(vmcs::guest_gs_access_rights::dpl::get() == 1UL);

    vmcs::guest_gs_access_rights::dpl::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_access_rights::dpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_access_rights_present")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::present::set(1UL);
    CHECK(vmcs::guest_gs_access_rights::present::get() == 1UL);

    vmcs::guest_gs_access_rights::present::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_access_rights::present::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_access_rights_avl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::avl::set(1UL);
    CHECK(vmcs::guest_gs_access_rights::avl::get() == 1UL);

    vmcs::guest_gs_access_rights::avl::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_access_rights::avl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_access_rights_l")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::l::set(1UL);
    CHECK(vmcs::guest_gs_access_rights::l::get() == 1UL);

    vmcs::guest_gs_access_rights::l::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_access_rights::l::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_access_rights_db")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::db::set(1UL);
    CHECK(vmcs::guest_gs_access_rights::db::get() == 1UL);

    vmcs::guest_gs_access_rights::db::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_access_rights::db::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_access_rights_granularity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::granularity::set(1UL);
    CHECK(vmcs::guest_gs_access_rights::granularity::get() == 1UL);

    vmcs::guest_gs_access_rights::granularity::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_access_rights::granularity::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_access_rights_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::reserved::set(0x10F00U);
    CHECK(vmcs::guest_gs_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_gs_access_rights::reserved::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_access_rights::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_gs_access_rights_unusable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_gs_access_rights::unusable::set(1UL);
    CHECK(vmcs::guest_gs_access_rights::unusable::get() == 1UL);

    vmcs::guest_gs_access_rights::unusable::set_if_exists(0UL);
    CHECK(vmcs::guest_gs_access_rights::unusable::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::set(100UL);
    CHECK(vmcs::guest_ldtr_access_rights::exists());
    CHECK(vmcs::guest_ldtr_access_rights::get() == 100UL);

    vmcs::guest_ldtr_access_rights::set_if_exists(2UL);
    CHECK(vmcs::guest_ldtr_access_rights::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::type::set(1UL);
    CHECK(vmcs::guest_ldtr_access_rights::type::get() == 1UL);

    vmcs::guest_ldtr_access_rights::type::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_access_rights::type::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_s")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::s::set(1UL);
    CHECK(vmcs::guest_ldtr_access_rights::s::get() == 1UL);

    vmcs::guest_ldtr_access_rights::s::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_access_rights::s::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_dpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::dpl::set(1UL);
    CHECK(vmcs::guest_ldtr_access_rights::dpl::get() == 1UL);

    vmcs::guest_ldtr_access_rights::dpl::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_access_rights::dpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_present")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::present::set(1UL);
    CHECK(vmcs::guest_ldtr_access_rights::present::get() == 1UL);

    vmcs::guest_ldtr_access_rights::present::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_access_rights::present::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_avl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::avl::set(1UL);
    CHECK(vmcs::guest_ldtr_access_rights::avl::get() == 1UL);

    vmcs::guest_ldtr_access_rights::avl::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_access_rights::avl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_l")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::l::set(1UL);
    CHECK(vmcs::guest_ldtr_access_rights::l::get() == 1UL);

    vmcs::guest_ldtr_access_rights::l::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_access_rights::l::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_db")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::db::set(1UL);
    CHECK(vmcs::guest_ldtr_access_rights::db::get() == 1UL);

    vmcs::guest_ldtr_access_rights::db::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_access_rights::db::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_granularity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::granularity::set(1UL);
    CHECK(vmcs::guest_ldtr_access_rights::granularity::get() == 1UL);

    vmcs::guest_ldtr_access_rights::granularity::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_access_rights::granularity::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::reserved::set(0x10F00UL);
    CHECK(vmcs::guest_ldtr_access_rights::reserved::get() == 0x00F00UL);

    vmcs::guest_ldtr_access_rights::reserved::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_access_rights::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_ldtr_access_rights_unusable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_ldtr_access_rights::unusable::set(1UL);
    CHECK(vmcs::guest_ldtr_access_rights::unusable::get() == 1UL);

    vmcs::guest_ldtr_access_rights::unusable::set_if_exists(0UL);
    CHECK(vmcs::guest_ldtr_access_rights::unusable::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_access_rights")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::set(100UL);
    CHECK(vmcs::guest_tr_access_rights::exists());
    CHECK(vmcs::guest_tr_access_rights::get() == 100UL);

    vmcs::guest_tr_access_rights::set_if_exists(2UL);
    CHECK(vmcs::guest_tr_access_rights::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_guest_tr_access_rights_type")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::type::set(gsl::narrow_cast<uint32_t>(1UL));
    CHECK(vmcs::guest_tr_access_rights::type::get() == 1UL);

    vmcs::guest_tr_access_rights::type::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_access_rights::type::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_access_rights_s")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::s::set(1UL);
    CHECK(vmcs::guest_tr_access_rights::s::get() == 1UL);

    vmcs::guest_tr_access_rights::s::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_access_rights::s::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_access_rights_dpl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::dpl::set(1UL);
    CHECK(vmcs::guest_tr_access_rights::dpl::get() == 1UL);

    vmcs::guest_tr_access_rights::dpl::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_access_rights::dpl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_access_rights_present")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::present::set(1UL);
    CHECK(vmcs::guest_tr_access_rights::present::get() == 1UL);

    vmcs::guest_tr_access_rights::present::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_access_rights::present::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_access_rights_avl")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::avl::set(1UL);
    CHECK(vmcs::guest_tr_access_rights::avl::get() == 1UL);

    vmcs::guest_tr_access_rights::avl::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_access_rights::avl::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_access_rights_l")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::l::set(1UL);
    CHECK(vmcs::guest_tr_access_rights::l::get() == 1UL);

    vmcs::guest_tr_access_rights::l::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_access_rights::l::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_access_rights_db")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::db::set(1UL);
    CHECK(vmcs::guest_tr_access_rights::db::get() == 1UL);

    vmcs::guest_tr_access_rights::db::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_access_rights::db::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_access_rights_granularity")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::granularity::set(1UL);
    CHECK(vmcs::guest_tr_access_rights::granularity::get() == 1UL);

    vmcs::guest_tr_access_rights::granularity::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_access_rights::granularity::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_access_rights_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::reserved::set(0x10F00U);
    CHECK(vmcs::guest_tr_access_rights::reserved::get() == 0x00F00U);

    vmcs::guest_tr_access_rights::reserved::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_access_rights::reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_tr_access_rights_unusable")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    vmcs::guest_tr_access_rights::unusable::set(1UL);
    CHECK(vmcs::guest_tr_access_rights::unusable::get() == 1UL);

    vmcs::guest_tr_access_rights::unusable::set_if_exists(0UL);
    CHECK(vmcs::guest_tr_access_rights::unusable::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_interruptibility_state")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_interruptibility_state::exists());

    vmcs::guest_interruptibility_state::set(1UL);
    CHECK(vmcs::guest_interruptibility_state::get() == 1UL);

    vmcs::guest_interruptibility_state::set_if_exists(2UL);
    CHECK(vmcs::guest_interruptibility_state::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_guest_interruptibility_state_blocking_by_sti")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_interruptibility_state;

    blocking_by_sti::set(1UL);
    CHECK(blocking_by_sti::get() == 1UL);

    blocking_by_sti::set_if_exists(0UL);
    CHECK(blocking_by_sti::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_interruptibility_state_blocking_by_mov_ss")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_interruptibility_state;

    blocking_by_mov_ss::set(1UL);
    CHECK(blocking_by_mov_ss::get() == 1UL);

    blocking_by_mov_ss::set_if_exists(0UL);
    CHECK(blocking_by_mov_ss::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_interruptibility_state_blocking_by_smi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_interruptibility_state;

    blocking_by_smi::set(1UL);
    CHECK(blocking_by_smi::get() == 1UL);

    blocking_by_smi::set_if_exists(0UL);
    CHECK(blocking_by_smi::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_interruptibility_state_blocking_by_nmi")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_interruptibility_state;

    blocking_by_nmi::set(1UL);
    CHECK(blocking_by_nmi::get() == 1UL);

    blocking_by_nmi::set_if_exists(0UL);
    CHECK(blocking_by_nmi::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_interruptibility_state_enclave_interruption")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_interruptibility_state;

    enclave_interruption::set(1UL);
    CHECK(enclave_interruption::get() == 1UL);

    enclave_interruption::set_if_exists(0UL);
    CHECK(enclave_interruption::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_interruptibility_state_reserved")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    using namespace vmcs::guest_interruptibility_state;

    reserved::set(1UL);
    CHECK(reserved::get() == 1UL);

    reserved::set_if_exists(0UL);
    CHECK(reserved::get_if_exists() == 0UL);
}

TEST_CASE("vmcs_guest_activity_state")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_activity_state::exists());

    vmcs::guest_activity_state::set(vmcs::guest_activity_state::active);
    CHECK(vmcs::guest_activity_state::get() == 0U);

    vmcs::guest_activity_state::set(vmcs::guest_activity_state::hlt);
    CHECK(vmcs::guest_activity_state::get() == 1U);

    vmcs::guest_activity_state::set_if_exists(vmcs::guest_activity_state::shutdown);
    CHECK(vmcs::guest_activity_state::get_if_exists() == 2U);

    vmcs::guest_activity_state::set_if_exists(vmcs::guest_activity_state::wait_for_sipi);
    CHECK(vmcs::guest_activity_state::get_if_exists() == 3U);
}

TEST_CASE("vmcs_guest_smbase")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_smbase::exists());

    vmcs::guest_smbase::set(1UL);
    CHECK(vmcs::guest_smbase::get() == 1UL);

    vmcs::guest_smbase::set_if_exists(2UL);
    CHECK(vmcs::guest_smbase::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_guest_ia32_sysenter_cs")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    CHECK(vmcs::guest_ia32_sysenter_cs::exists());

    vmcs::guest_ia32_sysenter_cs::set(1UL);
    CHECK(vmcs::guest_ia32_sysenter_cs::get() == 1UL);

    vmcs::guest_ia32_sysenter_cs::set_if_exists(2UL);
    CHECK(vmcs::guest_ia32_sysenter_cs::get_if_exists() == 2UL);
}

TEST_CASE("vmcs_vmx_preemption_timer_value")
{
    MockRepository mocks;
    setup_intrinsics(mocks);

    g_msrs[msrs::ia32_vmx_true_pinbased_ctls::addr] =
        msrs::ia32_vmx_true_pinbased_ctls::activate_vmx_preemption_timer::mask << 32;
    CHECK(vmcs::vmx_preemption_timer_value::exists());

    vmcs::vmx_preemption_timer_value::set(1UL);
    CHECK(vmcs::vmx_preemption_timer_value::get() == 1UL);

    vmcs::vmx_preemption_timer_value::set_if_exists(2UL);
    CHECK(vmcs::vmx_preemption_timer_value::get_if_exists() == 2UL);
}

#endif
